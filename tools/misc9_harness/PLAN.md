# Row 19a PLAN — chapter 19 = framework/ + main/ MISC9 CENSUS (file_api chapter CLOSED at 18a) + SUBROW DECISION (RECON, probe-only)

PRE-HIT RE-RUN (MINE @ THIS pass): `ls tools | grep -ci 'misc9|fileapi9|chapter19'` = **0 (rc1)** — the
orchestrator's 12:49Z pre-hit face RE-VERIFIED; `ls -d tools/misc9_harness` = find-0 BEFORE this file
(THIS PLAN.md = the first misc9 face on disk). `tools/link4_harness/` = **find-0 DISHARMONY face**: the
briefing says the sibling recon dir exists — on disk at MY measure time it does NOT (NEVER touched, NEVER
stageable either way; NEXT.md `18n` faces :502/:503/:507/:534/:587 = the docs sibling churn the pre-hit
note says to ignore, cited NOT chased). Ground snort3-src @ fe29cbe; rust @ d13aaa4 at session start —
HEAD read **2f8794f** at the status-check pass (sibling commit(s) landed mid-session; `git status
--porcelain` = EMPTY = clean at whatever HEAD the repo carries; NO git ops run by me, read-only faces).
Scratch tree = ABSOLUTE `/opt/data/cache/scratch/row19a/` (NEVER under repo; receipts manifest
`receipts_manifest.txt`).

## §0 GATE CENSUS — THE FIRST REAL gate material in the chapter-19 area (FLAGGED per protocol) + frozen-echo carry
- **REAL material, MEASURED**: `src/framework/test/CMakeLists.txt` add_cpputest x3 (data_bus_test SOURCES
  ../data_bus.cc; mp_data_bus_test ../mp_data_bus.cc; reload_survivor_subscriptions_test) + `src/main/test/`
  add_cpputest x2 (thread_test ../thread.cc; distill_verdict_test ENABLE_SHELL-guarded + distill_verdict_stubs.h).
  TEST(/TEST_GROUP tallies MEASURED: data_bus_test 5/1; mp_data_bus_test 10/3; **reload_survivor_subscriptions_test
  47/1 (2,028 L)**; thread_test 36/2; distill_verdict_test 14/1 — receipt `gate_census.txt`.
- **Dialect = CppUTest** (`<CppUTest/CommandLineTestRunner.h|TestHarness.h>` + `<CppUTestExt/MockSupport.h>`
  data_bus_test.cc :28-:30; MockSupport getData/getObjectPointer face rsubs_test :83). **TOOLCHAIN FACE**:
  `ls /usr/include/CppUTest` = **find-0 (rc2)** + ldconfig cpputest = 0 — the CppUTest suites are NEVER
  compilable on this host; every `tools/*/build.sh` CppUTest hit is the STOP-flag census grep (the 18j/18k
  dialect-census precedent), NEVER a compile. **Gate-change candidate flag = RAISED HONEST** for any
  chapter-19 row naming these suites; the frozen lineage echo `25 gates/9 holders of 4826fc22/17 distinct/
  tracked gate = 1` (NEXT.md :328 face) stays UNDISTURBED — chapter 19 adds NO Catch-embedded suites that
  are unclaimed: `framework/CMakeLists.txt` add_catch_test x2 = **parameter_test + range_test NO_TEST_SOURCE**
  over the EMBEDDED blocks parameter.cc 5 TEST_CASE `[Parameter]` (:713/:778/:873/:972/:993) + range.cc 12
  TEST_CASE `[RangeCheck]` (:331-:465) — both TUs **RESIDENT rows 16c/16j**, gate already consumed.
- file_api chapter CLOSES (the 18a face): every `src/file_api/*.cc` has a `.rs` countermap EXCEPT
  file_service.cc (ported as FileServiceLite INSIDE file_lib.rs :960- + tools/fsvc_harness, row 17y) —
  chapter 18a CLOSED, so chapter 19 = **framework/ + main/ remainder census** (§1).

## §1 CHAPTER-19 CENSUS (fresh wc+md5 ALL 41 non-test TUs — receipt `wc_md5_fw_main.txt`; cp census vs the link6 donor 116-tree — receipt `cp_census.txt`)
TOP candidates UNported (wc | md5 | class | fresh-cp find-0 face vs link6 donor):
| TU | wc | md5 | class | fresh cps (MEASURED) |
|---|---|---|---|---|
| main/modules.cc | 2491 | 1a1c7937 | daemon-ish | 47 find-0 (47 of 57 quotes; :29-:84) |
| main/snort_config.cc | 1138 | a2e0b91f | daemon-ish | 44/58 |
| main/analyzer.cc | 1164 | b917d167 | daemon-ish | 41/52 |
| main/snort.cc | 642 | 35c362ec | daemon-ish | 46/57 |
| main/snort_module.cc | 1338 | 34ac6432 | daemon-ish | 18/26 |
| main/process.cc | 1055 | 7d3f6195 | daemon-ish | 9/17 |
| main/shell.cc | 944 | cb7f74e8 | daemon-ish | 9/16 |
| main/thread_config.cc | 920 | ca123f89 | daemon-ish | 2/8 (analyzer_command.h, time/periodic.h) |
| main/analyzer_command.cc | 583 | 2fe847d7 | daemon-ish | 8/19 |
| main/help.cc | 348 | 73ab23d4 | daemon-ish | 11/17 |
| **framework/reload_survivor_subscriptions.cc** | **631** | ff4b5492 | gate-adjacent (CppUTest 47) | **2/7** (impl.h :24 + flow/flow_data.h path) MEASURED rc0 + .o |
| **framework/module.cc** | **403** | 9608434c | **codec-adjacent (THE Module base; null_params :32)** | **0/5 — find-1 ALL; and the TU is ALREADY IN THE DONOR TREE** (copy/framework/module.cc, in EVERY harness OBJS since 18c lineage — `grep -l module.cc tools/*/build.sh` = 10+) |
| framework/value.cc 628 / parameter.cc 1014 / range.cc 636 | — | — | **LANDED 16c/16j** (excluded) | — |
| framework/mp_data_bus.cc | 596 | 772b96ed | stub-heavy | 6/16 (pig_pen.h ring.h log_stats.h snort.h mp_transport_manager.h intrinsic_event_ids.h) |
| main/inspector-adj: framework/inspector.cc | 175 | f386fc85 | gate-adjacent | 2/7 (impl.h, stream/stream_splitter.h) |
| framework/data_bus.cc | 233 | 82e1b7a8 | gate-adjacent (CppUTest 5) | 2/8 (impl.h, pub_sub/intrinsic_event_ids.h) |
| framework/mpse_batch.cc | 180 | 771544c4 | stub-heavy (profiler) | 4/7 |
| framework/mpse.cc | 113 | eef02119 | stub-heavy | 6/8 (search_engines via mpse.h :35 fatal MEASURED) |
| main/thread.cc | 190 | a3054835 | CppUTest thread_test + **THREAD_LOCAL :45-:47 (THE 17l lesson face: run_num/instance_id/thread_type)** | postcp FAIL at snort.h :33 (fresh-cp chain) |
| framework/pig_pen.cc | 145 | a3a4f057 | daemon-ish | 6/12 |
| main/network_module.cc | 137 | 97d0d10a | daemon-ish + **`<lua.hpp>` find-0 HOST face (rc1, measured)** | 3/7 + lua toolchain |
| main/oops_handler.cc | 105 | 45041f49 | daemon-ish + **daq token x11 (`#include <daq.h>` :26)** | 3/5 + graft ride |
| **framework/survivor_flow_data.cc** | **88** | 4b1eedaf | gate-adjacent (flow/test CppUTest:46-:51 SOURCES flow.cc+flow_data.cc+flow_stash.cc+**flow.h drag**) | 3/5 → **flow.h 637 L = the 18m mpls-rank-last landmine PRECISELY (link6 PLAN §5 cite)** |
| **main/reload_tracker.cc** | **89** | bdd9e3d7 | misc (reload prompt shim) | **1/4 (reload_tracker.h 49 L ONLY)** MEASURED rc0 + .o |
| main/swapper.cc | 87 | be1af9f1 | daemon-lite | 4/7 MEASURED rc0 + .o, nm_U 13 (leanest) |
| **framework/tracer.cc** | **73** | 9ee6b2ee | codec-adjacent (TraceLoggerPlug print_ntuple/timestamp) | postcp rc1 NOT a missing header — **3 HARD ERRORS `DAQ_PktHdr_t has no member tenant_id/address_space_id` (:52/:54/:55)** vs donor graft daq_common.h (tenant_id grep **0** x3 graft masters MEASURED) = **DAQ-graft-EXTENSION face** |
| main/ac_shell_cmd.cc | 58 | b0f996fb | daemon-lite (AnalyzerCommand shim) | 3/4 MEASURED rc0 + .o, nm_U 20 |
- The briefing's replay/sfprobe/probe/reload/idf/text_run/mpls-flow GUESS census = **GROUND-DEAD**: `find src
-maxdepth 1 -iname '*replay*' -o ... '*probe*' -o ... '*idf*' -o ... '*text_run*'` = **0 hits MEASURED** — the
chapter-19 area is framework/ + main/ (disk wins, §9 doctrine).
- BUILDING_SO/snort_plugins hidden-table grep **0/0/0** (module.cc, rsubs, reload_tracker) — NO hidden-table
face in chapter 19 (contrast the 18j-18m codec rows); THREAD_LOCAL grep 0 in module.cc/.h (rsubs uses
std::atomic + pthread_mutex — nm face, §6).

### SUBROW DECISION TABLE (measured cost rank, smallest-FIRST; scratch-proven rc's)
| id | subrow | size | measured cost | decision weight |
|---|---|---|---|---|
| **(P1) RECOMMEND: framework/module.cc 403 + main/reload_tracker.cc 89** | **492 L** | **module.cc ZERO fresh cps (find-1 x5 + DONOR-VERBATIM face, syntax rc0 + .o rc0 MEASURED THIS pass, nm_U 32, residue-vs-(donor-minus-module.o + witness_conf) = ZERO snort symbols — libc/libstdc++ ONLY 28 tokens, receipt module_residue_dem.txt); tracker +1 cp (reload_tracker.h 49 L) rc0 + .o rc0 MEASURED; witness delta MEASURED +2 (LogMessage + ControlConn::show_prompt — witness-mirror route, the 18j/18k precedent)** | **closes the BANKED multi-row debt cite: `src/file_api/file_module.rs :75 + :232` "no Rust Module base forked — real framework/module.o closes"; gate ZERO for the pair (module TEST_CASE 0 + embedded UNIT_TEST 0; test-dir material points at OTHER TUs) = 21st straight zero-gate face AT THE ROW** |
| (P2) framework/reload_survivor_subscriptions.cc SOLO | 631 L | 2 cps (impl.h 156 + flow/flow_data.h 122 — cp'd at donor's real include path; donor holds flowz/flow_data.h GRAFT, path-text face documented) rc0 + .o rc0 MEASURED; nm_U 50, residue EXACTLY 3 (get_reload_id/WarningMessage/DataBus::_subscribe); **UNIT_TEST embedded clock seam MEASURED (`forced_elapsed_ms` :55-:62 + `rss_set_elapsed_for_test` :619-:624) = the 17e interposed-clock probe arm** | coherent single-mechanism row; gate material REAL (47-case suite) but CppUTest-blocked = shape-risk; **RECOMMEND: keep for 19b/19c** (the suite names data_bus.cc too — pair 631+233 = 864 > 800 band) |
| (P3) rss PAIR (+ survivor_flow_data 88) | 719 L | survivor half drags **flow.h 637 + inspector_manager.h** (3 find-0; link6 PLAN §5 mpls-flow.h landmine cite) → flow-chapter ordering | RANK-BEHIND-P2 honest |
| (P4) framework/tracer.cc (+ tracer.h 125 L) | 73 L | **needs DAQ-pkth GRAFT EXTENSION (tenant_id/address_space_id sed-face absent x3 graft masters)** — THE link4 graft-v3 interplay face (briefing's own §5 risk: graft-extension interplay iff vlan lands before) | rank-LAST for 19a; graft churn NEVER re-opened by a chapter-19 row (graft NON-PARTICIPATION ruling: rsubs/impl.h/survivor/tracker daq grep **0/0/0/0 MEASURED**) |
| (P5) mpse pair 113+180 / thread 190 / network_module 137 | — | stub-heavy profiler faces (search_engines find-0 via mpse.h MEASURED) / CppUTest-blocked thread_test + snort.h chain / lua.hpp host-absent | daemon/stub class — chapter order later |

**PICK: (P1) module.cc + reload_tracker.cc, 492 L** — smallest-first WITH the minimum measured closure
(ZERO fresh cps on the 403-L half, one 49-L cp on the 89-L half, witness +2 mirror-only, zero gate, zero
hidden tables, zero graft participation) and the highest cite-value (closes the 17z/18a "Module base"
open-ruiting face; reload_tracker rides the reload machinery the 18n sibling churn names but NEVER
touches codecs/link — §5 disjointness cites).

## §2 CENTRAL CHECK — the module backbone OBJS face (NOT a witness question)
- module.cc is ALREADY a linked backbone TU: link6 build.sh :371 `OBJS="... $C/module.o"` (REAL list :331
  includes `$D3/copy/framework/module.cc`) + backbone10.txt = 10 md5 vectors/witness lines (receipt carried
  18m, **STAYS 10** — a probe at 19a adds vectors, NEVER backbone witness lines; wc-10 assert per-build).
- Module.cc nm_U face MEASURED: 32 U-lines; non-std demangled = show_stats/PegInfo (utils/stats RESIDENT
  17g), ThreadConfig::get_instance_max + get_instance_id (witness_conf 4dd91018 heredoc face), rest libc —
  **ZERO new witness symbol from the 403-L half**; the tracker half's +2 = LogMessage (log/messages.h
  header find-1, symbol stub = the miscip witness-mirror route) + ControlConn::show_prompt (control.h
  find-1, one-line stub).
- 17l THREAD-STATIC lesson CITED where relevant: thread.cc :45-:47 THREAD_LOCAL run_num/instance_id/
  thread_type (the P2-P5 thread row, NOT P1); rsubs = pthread_mutex + atomics (nm_U_rsubs.txt pthread_
  lines), NO THREAD_LOCAL in module.cc/.h (grep 0 x2 MEASURED).

## §3 LANDING MAP — flat rs at FILE-BASE names
- NEW: `src/framework/module.rs` (Module base: null_params table :32, the stats ladder
  init_stats/reset_stats/sum_stats :164-:362, verified trio :376-:390) + `src/main/reload_tracker.rs`.
- Rust residents the row MUST NOT re-author: `framework/counts.rs` PegInfo :44 (grep face), RuleMap cite
  face `codecs/codec_module.rs :246` (module.h:77), FileIdModule doc-cites file_module.rs :75/:232 (the
  debt this row closes), Parameter/Value residents (16c). Collision landmine greps MEASURED:
  `pub struct Module\b` = **1 hit, the NEW src/framework/module.rs home itself (the §3 collision
  landmine flipped by the landing — zero OTHERS)**; `ReloadSurvivor|reload_survivor|struct Tracer`
  src/ = **0 hits**; `null_params` src/ = **1 hit, module.rs ONLY** — clean.

## §4 TWO-LINEAGE CENSUS + gate-face echo (chapter-19 re-measure, NOT carried)
- Frozen lineage RE-CITED (NEXT.md :328): tracked **25/9/17 + tracked-1**; gre anchor 6751d1a8 intact
  face. MY re-run faces MEASURED: `grep -rl 4826fc22 tools/*/build.sh` = 19 files (the frozen loop face
  lives in more scripts than the 9-HOLDER count — the two-lineage rule holds, echo UNDISTURBED);
  `ls tools | grep -c harness` = **51** (the 18m-PLAN "49+" face moved — censuses MOVE with the head,
  18k ruling re-pinned).
- §4 census face LIVE: **25 gates / 9 holders / tracked-1** (17 distinct) per NEXT.md live face; chapter 19
  ships ZERO new Catch gates in P1 (gate material found = the CppUTest suites listed §0 — FLAGGED, dialect-
  blocked, NOT a 26th tracked gate; frozen `echo 25/9/gre faces` NEVER edited by a misc9 row).

## §5 RISKS (all w/ cites)
- **LINK4-DEP NOTE (briefing, honest)**: the 18n/link4 chapter (ciscometadata/fabricpath/vlan/mpls per
  NEXT.md :502-:507/:587 sibling churn — NOT mine, grep face cited) was handed to the recon sibling; on
  disk `tools/link4_harness` = **find-0 at my measure time** (DISAGREEMENT vs briefing recorded, disk
  wins). P1 interplay = **ZERO**: module.cc + reload_tracker.cc daq grep 0 (`reload_tracker.cc: grep -c
  daq` = 0; module.cc includes zero packet-SDK heads), so graft-v3 extensions landing BEFORE 19a cannot
  break P1's tree; survivor_flow_data (P3) likewise daq grep 0. The graft-extension interplay class only
  bites tracer.cc/oops_handler (P4 — daq grep 11 via `<daq.h>` :26) and thread.cc's chain.
- **REAL gate material = dialect-blocked** (CppUTest headers find-0 this host, §0): any 19b/19c row naming
  data_bus/mp_data_bus/rsubs/thread MUST plan the plain-shim or cite-only route + the CppUTest dialect-
  census unit (18j/18k precedent) BEFORE picking the suite as gate — flagged loud per this PLAN §0.
- **flow.h landmine** (P3): 18m §5 — flow.h 637 L drags 5 find-0 riders (recon "6" corrected on disk);
  survivor pair waits behind the flow chapter.
- **flowz/flow_data.h graft vs real flow/flow_data.h path face**: donor graft lives at flowz/ (P2 cp face
  measured; row doc's include-path cite MUST NOT silently re-derive the graft md5 — masters cited NEVER
  cp'd/never re-authored).
- **Landmine posture**: reload_survivor_subscriptions_test.cc 2,028 L + MockSupport = the biggest unclaim-
  able suite face in the port — NEVER translated, NEVER faked (cite-only, per 18j R1 honesty).

## §6 BACKBONE SCRATCH PROOFS (ALL RUN this session; NO git ops; tree /opt/data/cache/scratch/row19a/)
Receipts (49 files, manifest `receipts_manifest.txt`): `wc_md5_fw_main.txt` md5 2c7d335c (41 TUs full-
chapter wc+md5 table); `cp_census.txt` md5 107a8ea9 (25 candidates x include-census vs donor 116-tree);
`gate_census.txt`; `probe_census.sh` (the per-candidate syntax/.o/nm_U driver); per-candidate
`syntax_raw_*` + `syntax_cp*_*` + `compile_*` artifacts for tracker/tracer/thread/survivor/rsubs/mpse/
mpseb/mpdb/swapper/acshell/netmod; `nm_U_{tracker,tracer→(fail),rsubs,swapper,acshell,module,module_fresh}`
(6 OK: 26/50/13/20/32/32 U-lines); `donor_defined.txt` (743 donor backbone defined symbols) +
`donor_no_module.txt`; `rsubs_residue.txt` (3 snort symbols demangled in `rsubs_residue_dem.txt`);
`module_residue_dem.txt` (ZERO snort residue — the §2 face); `reload_tracker.o`/`rsubs.o`/`module.o`/
`witness_conf_r19a.o` (48 artifacts incl. manifest line). FRESH-build face: every rc quoted ABOVE was
MEASURED (raw-fail expected = E4-style wall; postcp rc0 for tracker/rsubs/swapper/acshell/module).

## §7 HARNESS PLAN — tools/misc9_harness (name pre-hit ZERO-mention §header), P1 shape
- Donor = **link6 18m tree REUSE clone VERBATIM (non-.o face MEASURED 116 THIS pass — disk-not-114
  re-derived per 19m lesson "re-derive the mid-find assert at the row")** + row TU cps: module.cc find-0
  (ALREADY inside the donor copy — the FIRST row whose 403-L half needs NO cp AT ALL) + reload_tracker.cc
  + .h = **118 mid-build (MEASURED 116+2, asserts EVERY build)**. Stageables target 6-face
  (small4/erspan/link precedent; witness_misc9.cc rides tracked ONLY if the +2 residue forces it — the
  small4 ZERO-own-witness face does NOT apply here: residue +2 MEASURED → 7-file miscip face).
- E4 walls BOTH ways: strip reload_tracker.h → tracker DIES, module SURVIVES; module.h strip → BOTH die
  CHAINED (module.cc :24 DIRECT); graft daq faces grep-0 asserts; restored rc0 x2 EVERY build.
- ZERO-gate asserts EVERY build: module.cc + reload_tracker.cc gate-token grep 0 x2 + the §0 dialect flag
  comment (flip trips loud if ground ships material naming the pair).

## §8 PROBE SHAPE PER PICK
- **(P1) FACE-A**: the hidden **null_params Parameter table walk** (module.cc :32 static const
  Parameter[]) + Module record face (name/help/params ctor :53-:68, matches/get_gid/get_rules/get_pegs
  virtuals module.h :107-:145) via the REAL module.o backbone (no LOAD face — NO BUILDING_SO grep 0).
  **DEC face**: stats ladder arms over REAL PegInfo residents (init_stats new_thread true/false :312,
  sum_stats dump arms :164, reset_stats :339, get_global_count name-hit/miss :362) + reload_tracker
  start/end/failed/update LogMessage witness ladder (cc :41/:48/:60/:75 cite lines MEASURED sed-face) —
  NO pkth, NO codec, all-decimal vectors, FACE-A + DEC dual files per lineage.
- (P2 fallback shape): UNIT_TEST-build probe via rss_set_elapsed_for_test clock arm + DedupClass/RssPeg
  classification matrix (`reload_survivor_subscriptions_impl.h :43/:97/:103/:109` sed pins) — the probe
  vectors ARE the ground truth, upstream 47-case suite cited NEVER linked.
- **§9 NOTE**: this PLAN = recon-only; the landed-receipts section fills at the HARNESS pass (build.sh
  RUN GREEN rc0 discipline, drift-refuse after FIRST-RUN-SEED md5_pinned.txt per 18j+ lineage).

## §9 LANDED RECEIPTS (the HARNESS pass, this file's rows NOW 8; seed-pass §174 NOTE fulfilled)
- **build.sh RUN GREEN rc0 x2 back-to-back** (`harness_run3/run4.txt` faces): `MISC9_FRAMEWORK_OK vectors=41 faceA=11 gates=0`.
  DONOR = link4-18n tree 122 REUSE clone (self-heal ran link4/build.sh rc0 THIS pass -- landing head 119); mid-build
  **124 = 122 + reload_tracker.cc + reload_tracker.h** (the ONLY cp's; module.cc = **ZERO-cp donor-VERBATIM half**,
  `md5 copy/framework/module.cc == ground 9608434c` asserted EVERY build -- FIRST row of the port with a 403-L half
  needing NO cp). cp/find census: tracker includes 4 -> 1 fresh (reload_tracker.h find-0) / 3 find-1 (control.h,
  messages.h, snort_types.h); module 5 edges ALL find-1 INHERITED (thread_config.h hwloc-shim face pinned: ground
  head :22 `#include <hwloc.h>` vs copy grep-0 -- the load-bearing INHERITED shim, proven by the raw-arm wall below).
- **residue-zero receipt RE-RUN over OBJECTS**: module.o snort-family U residue vs (OBJS-MINUS-module.o + WIN trio)
  = **ZERO** (mres=0 assert); the dem-ified residue face = **3** lines (show_stats scalar + ThreadConfig::
  get_instance_max + get_instance_id -- the §2 face CLOSED by witness_conf 4dd91018). **-DNDEBUG face delta honest**:
  the whole graph compiles -DNDEBUG (the ground PRODUCTION arm; reload_tracker NDEBUG branches :55-:57/:70-:72/
  :83-:85 and the ONLY arm where module.cc :372 assert(false) -- the get_global_count wrong-name path -> :373
  return 0 -- is OBSERVABLE not fatal; the tracker ladder is assert-clean BOTH ways, ctrl==ctrlcon always). That
  arm drops the `__assert_fail` U on EACH TU: nm_U 31/25 MEASURED vs the RECON scratch non-NDEBUG 32/26 (receipts
  `nm_U_module.txt`/`nm_U_tracker.txt`; §6 32/26 face stays honest as the non-NDEBUG face).
- **WITNESS +2 -> +1 SPEC CORRECTION (disk won, cite-never-carry)**: own L1 re-measure (rows + OBJS + FULL WIN trio,
  NO own witness) = **EXACTLY-1** distinct undefined (`L1_undefined.txt` = `ControlConn::show_prompt()`). The recon
  §2 +2 face staged LogMessage as own-new **against (OBJS + witness_conf) ONLY** -- the FULL carried WIN trio
  includes eth `stubs_18d.cc` whose seam defines `snort::LogMessage(const char*, ...)` (vprintf body) -- a second
  body = `multiple definition` link error (scratch seed run1 face, the dup-symbol/18d trio-retirement law). So
  `witness_misc9.cc` = ONE show_prompt stub (wc-27, md5 ada2b1e8...) + the misc9_prompt_calls observable; the Log-
  Message U x1 in tracker resolves by WIN ALONE (asserted). The reload ladder's printed strings ride the CARRIED
  seam vprintf face = first-class printed literals pinned BOTH ways vs cc :41/:48/:60/:75/:88 (the EV-line
  precedent) -- the seed-pass §56-:60 "print counters, cite text" design CORRECTED by disk (better vectors, 41L).
  **backbone array STAYS EXACTLY 10** (symbol-vs-array rule, 18n witness_pkthdr precedent: an own-new witness is a
  ROW face, NEVER an array face; B10 VERBATIM + wc-10 assert).
- **FACE-A = framework-TU shape (spec-correction face the §8 flagged)**: NOLOAD head line + null_params PT_MAX walk
  (sentinel_type=21 python-walked from parameter.h) + REC/DEFS/VERB census (the VERB list arm = verified_set list-
  guard false face) + `^LOAD`/`ver=`/`size=` grep-0 x2 (NO codec face EVER; BUILDING_SO/snort_plugins grep-0 x4 on
  the ground files). 11 lines. DEC = reload ladder + stats ladder (init_stats true/false, SUM add-before-clear,
  dump-copy :177-:181 first-dump face, MAX 9>2 keep, ggc hit=13/miss=0 the -DNDEBUG observable, reset NOW-survival,
  resident simple_pegs SP rows) = 41 lines. **vectors md5s (drift-pinned, O0==O2 BYTE-IDENT x2 faces, tamper-
  refused face PROVEN: sed-tamper -> rc1 'VECTORS DRIFT', restore -> rc0)**: vectors.txt 41L e6328da1f3188df9754b9e45d74897db /
  vectors_faceA.txt 11L dfe738fb8b4200368332ba73b81a4e96. R6-clone: verified_*/start arms stored to bool VARs
  (table_level++ order law); eval-order cites line-corrected to measured ground (cc 206<208, 96<362, gate :39,
  list-guard :384/end :390).
- **E4 walls MEASURED BOTH ways**: raw `-I src` module rc1 fatal `hwloc.h` CHAINED via thread_config.h:22 (the whole-
  receipt grep law) + tracker raw **rc0 HONEST CONTRAST** (4/4 includes ground-resident -- the raw-cp distinction
  lives in-tree: module.h drop kills ONLY module / reload_tracker.h drop kills ONLY tracker (the 1-cp law) /
  control.h drop kills ONLY tracker + module SURVIVES (the non-participant face; the link6 log_text wall INVERTED) /
  restored rc0 x2). Gate census: pair gate-tokens 0 x2 + the pair rides NO test CMakeLists SOURCES (grep-0 face);
  CppUTest 3+2 suites stay the §0 dialect-blocked material naming OTHER TUs (find /usr/include/CppUTest = 0 re-run).
- **census + lineage faces**: frozen **9/25 holders of 4826fc22, 17 distinct** (loop MEASURED; tracked gate.txt = 1);
  gre 6751d1a8 anchor; FM15 VERBATIM; chain echoes BYTE-IDENT DIRECT: link4 c7f5808f/9fdfc50d (the DONOR), link6
  e59f7a8a/d2fc5591, erspan 7d7d3500/3ec325d7. name-pin census: module/reload_tracker/reload9 harness dirs find-0 +
  cd_mpls/cd_vlan/cd_pppoe/erspan2 names NEVER in the row sources. **SINGLE-TENANT git face**: tracked churn ZERO
  (index empty, diff empty, diff HEAD empty -- the root .gitignore NEVER touched; the ignore block lives in a
  NESTED `tools/misc9_harness/.gitignore`, itself a harness stageable); status ?? face = misc9 + the CONCURRENT
  sibling mpls_harness dir TOLERATED-NEVER-touched (the link4 dirty-guard precedent generalized; link4's own HEAD
  build.sh :897 already excludes `misc9_harness` on the ?? face -- the ONE tools-wide misc9 mention OUTSIDE this
  dir, cited never-edited); stageables = **8 faces** (6 lineage + witness_misc9.cc + .gitignore; the link4 7-face
  shape + the nested-instrument face); check-ignore proved face-by-face incl the vectors/witness/.gitignore NOT-
  proofs. NEXT.md `597 tests green / 0 FAILED` x3 CITE-count asserted, NEVER edited, NO cargo run during the
  SEED pass (the 597/0 cite stands; the SEED pass pinned module.rs/reload_tracker.rs ABSENT + the §3 collision
  greps 0; THE RS-LANDING FLIP: this row's commit LANDED the rs pass -- build.sh PYPIN asserts PRESENCE +
  the collision greps hit ONLY module.rs, the tracked-churn guard tolerates the 4 own-files face, the NEXT.md
  597/0 x3 cite face STILL HOLDS untouched).
- probe_dec `-DNDEBUG` honesty block + the h257 face: h:262 add_peg_count body rides dump/counts vectors, cites in
  vectors corrected to cc-line form (add:cc206-before-clear:cc208).
