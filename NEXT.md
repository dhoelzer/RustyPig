# NEXT.md — takeover context & plan (2026-11-21, post-18k: misc leftover trio landed, misc/ tail CLOSED; donor = misc3_harness, ZERO-gate head + THE graft-v2 heredoc face + tracked SFDAQ-pair witness + 111 post-strip copy tree)

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

Current state (measured at this 18k verify-mode docs pass): plan rows
1–18k DONE. **111 commits at HEAD d7aa42c** (`git rev-list --count
HEAD` THIS pass; origin/master == HEAD, `rev-list --count` both **111**
+ `ls-remote` sha match re-verified; this docs commit lands as the
**112th**). **573 tests green / 0 FAILED** (full `cargo test` re-run AT
THIS docs pass: summed `test result` lines programmatically = 573
passed / 0 failed over 69 result lines; 573 = 565 at 18j + 8
`tests/misc3_parity_test.rs` (wc 781 L, `grep -c '#\[test\]'` = 8
re-measured THIS pass); the three new TUs
`src/codecs/{cd_llc,cd_vxlan,cd_user}.rs` 290 + 218 + 333 = **841 L**
carry ZERO in-crate `#[test]` (grep 0/0/0 re-run THIS pass); `cargo
clippy --all-targets` **0 warnings** (forced relint THIS pass: touched
every .rs, `Finished` line, `grep -c '^warning'` = 0), 52,197 lines
Rust across 153 `src/*.rs` files (`find src -name '*.rs' -exec wc -l
{} +` THIS pass), 42 `tests/*_parity_test.rs` whole-transcript replay
tests, 442 tracked files (`git ls-files | wc -l`), 49 `tools/*_harness`
dirs. GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD **ff9f931 = row 18j wiki trio LANDED** and
the wiki REMOTE is still ff9f931 (`git -C /tmp/RustyPig.wiki ls-remote
origin refs/heads/master` verified THIS pass); `git grep 'row 18k'
HEAD -- '*.md'` = **0 hits AT THE COMMIT FACE** verified THIS pass —
the 18j trio text is present + landed, `row 18j` worktree greps hit).
**NEW measured wiki face — the 18k trio is PREPARED-IN-WORKTREE but
NOT COMMITTED** (re-measure before typing anything about it — the
status has CHANGED twice between passes before):
`git -C /tmp/RustyPig.wiki status --porcelain` = `M Porting-status.md`
(the 18k status row at :101 + chapter note at :113 ALREADY carry
'row 18k' worktree text) + `?? dev_block_18k.txt` (115 L, mtime
08:20Z) while `Deviations-from-Snort-3.md` grep '18k' = **0** (the
deviations section is NOT yet applied) and nothing is pushed. The
WIKI phase must: commit that prepared pair + track dev_block_18k.txt +
apply the row-18k deviations section from KNOWN DEVIATIONS.md
**:3522-:3636** (115 L / 7 bullets — verify the block matches the
dev_block file before pushing) + re-measure the stats line LIVE at
that pass (the wiki HEAD moved mid-ledger before; NEVER trust this
file's numbers for the stats commit) + push ONCE. This docs pass
touched the wiki ZERO times — NEVER edit `/tmp/RustyPig.wiki` outside
the WIKI phase.

## 18k close-out — VERIFY MODE (plan row + deviations shipped WITH code commit d7aa42c; this pass greps-verify + re-ground rather than append)
Like 18b-18j, 18k's plan row and deviations section shipped inside the
CODE commit, so this docs pass is a verification pass. Everything below
was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18k |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:90) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what d7aa42c shipped (`git show
  --shortstat d7aa42c`: **15 files changed, +2,906 / -0** — the
  expected 15-path face: 7 harness files + 3 src TUs + mod.rs + parity
  test + .gitignore + plan + deviations; plan-first staging face).
- **Deviations section**: `grep -c '^## codecs misc leftover trio (row 18k'`
  = **1** at **:3522**, running to EOF **:3636** = **115 L**, **7
  bullets** (`sed -n '3522,$p' | wc -l` and `grep -c '^- \*\*'` THIS
  pass). **Verdict: ADEQUATE-READ-LEAVE** — the graft-v2 daq.h-REUSE
  face (cd_user.cc:101 `DIOCTL_QueryUsrPCI qup = { raw.daq_msg,
  nullptr }` re-read THIS pass demands the v2 const-`void*` face; the
  mid-build 112 NEVER a pin / POST-STRIP 111 = 105+3+3 owns the
  assertion), the SFDAQ seam (witness-mirror x2, SYNTHETIC class-stub
  per the 18j precedent, the cc:103 ground-SEGV chain-call cited
  NEVER faked, the ioctl-fail/`!pci` legs cited-NEVER-armed through
  the always-success fixture), the mod_ctor 1/0/0 asymmetry — sed
  re-verified byte-true THIS pass: llc `mod_ctor` cc:156 + `mod_dtor`
  cc:159 slots :179/:180 vs vxlan cc:113/:114 + user cc:147/:148
  nullptr pairs —, the hidden-BUILDING_SO census EXTENDED x3, the
  set_key address-literal ruling (dotted quads sed-CITE-only, sp/dp
  12345/54321 land as observables, FIXIT-L cc:70 pinned), the
  dup-vs-import ruling per the banked cd_icmp6.rs:179-:183 pre-ruling
  (cd_udp.rs :147-:149 re-read this pass: PROTOCOL_ID_VXLAN 0x0108 +
  GENEVE 0x0109 twins), and the dead-defines + zero-event integrity
  face (SIX dead llc defines grep-count 1 x6 re-measured by EXACT
  token: ETH_DSAP_SNA/ETH_SSAP_SNA/ETH_DSAP_STP/ETH_SSAP_STP/
  ETH_ORG_CODE_ETHR/ETH_ORG_CODE_CDP all = 1; the two USED names
  ETH_DSAP_IP/ETH_SSAP_IP = 3/3) ALL re-grounded. **NO in-repo cite
  drift found** — and the orchestrator briefing face matched the live
  face IN BOTH DIRECTIONS THIS pass (the rare clean one, recorded
  honestly): trio ground md5s re-md5'd = `df63cf75b1bf…`/
  `c8479a2aa67e…`/`01e41407b300…` (matches the 18j-era + wiki cites),
  wc 198/133/167 = 498 (`wc -l` re-run, and the harness's own -eq 498
  sum pin at build.sh :50 re-read), Rust 290+218+333 = 841 (wc),
  vectors 18 L `e75f7385779aa89c365dd2ce4a208b67` + FACE-A 19 L
  `fe1189c6c78139b8828c1a8071e3df28` byte-stable pre+post rebuilds +
  witness_trio.cc 35 L `ef50cd2f8cdb4b9fa3d483e702bd73be`, witness
  delta EXACTLY +2 {SFDAQ::get_local_instance, SFDAQInstance::ioctl}
  (harness echo re-read, below), backbone census 8->10 PIN live
  (`backbone10.txt` = EXACTLY 10 md5 lines incl `ef50cd2f` +
  `4dd91018`, re-counted THIS pass), 3 fresh cps 54/72/105 + find-111
  (harness echo + re-found OUTSIDE the script, below), graft-v2 28 L
  heredoc face (`EOFGRAFT` block build.sh :220-:244 = 30 fenced lines
  carrying EXACTLY the flipped `typedef const void* DAQ_Msg_h` + the
  6 SDK typedefs DAQ_IoctlCmd/DAQ_Config_h/DAQ_Instance_h/DAQ_Verdict/
  DAQ_RecvStatus/DAQ_Stats_t + `#define DAQ_SUCCESS 0`), 3 fresh cps
  daq_user.h 54 + sfdaq.h 72 + sfdaq_instance.h 105 (54+72+105 = 231;
  the 28 L = the typedef-delta face, verified NOT conflated). The
  18j "176-vs-175 L / 11-vs-15 bullets" half-wrong lesson KEEPS its
  teeth — zero correction needed here is measurement, not luck.
- **Harness FRESH x2 THIS pass, rc 0 both runs**: `MISC3_HARNESS_OK
  vectors=18 faceA=19 gates=0` tail verbatim BOTH, LOGS byte-ident run
  A vs B (`cmp` rc 0, receipts
  `/opt/data/cache/scratch/row18ldocs/misc3_{A,B}.log`). Runner echoes
  re-read in the fresh logs: copy tree **mid-build 112 / post-strip
  111** ("105 miscip post-strip + daq.h REUSE + 3 fresh hdr cps + 3
  row TUs ... the REUSE graft NEVER stays"); an INDEPENDENT
  post-run `find tools/misc3_harness/copy -type f ! -name '*.o' |
  wc -l` = **111** confirms the face OUTSIDE the script's own asserts;
  row-TU nm echo `llc=22 vxlan=10 user=13 union=28 | union-mangled=33
  (tunnel_bypass census 0/1/0 -- HOOK rides witness_18f CARRIED, zero
  new bypass)`; witness delta echo `L1 undefined-EXACTLY-2
  (SFDAQ::get_local_instance + SFDAQInstance::ioctl ONLY) ->
  +witness_trio GREEN, own-new T census EXACTLY-2; get_proto_name row
  census 0 -> witness_miscip c5b498ff DONOR-INHERITED cite NEVER
  linked`. ALL 7 tracked faces re-counted
  (`git ls-files tools/misc3_harness` = **7**: build.sh 775 L
  `1b9978d6…`, PLAN.md 118 L, probe.cc 53 L, probe_dec.cc 115 L,
  vectors.txt 18 L, vectors_faceA.txt 19 L, witness_trio.cc 35 L).
  The graft-v2 heredoc re-read THIS pass (see deviations bullet); the
  on-disk misc3 copy daq_common.h graft-v2 face = md5 `fead0027…`
  while the **fmod home v16 graft `tools/fmod_harness/copy/
  daq_common.h` stays `f683749cda1d7c4acef832d880df3b73` 16 L
  byte-ident** (sed-asserted by misc3 build.sh :155-:156 EVERY build
  + re-md5'd OUTSIDE the harness THIS pass — the v2 face NEVER leaks
  to the frozen donor). Tools-wide `find tools -name daq.h -type f` =
  **EXACTLY 1** (the daq3 33 L `73fdbc39…` tracked graft, sha-re-
  verified; second-landing census honest). .gitignore misc3 block
  **:494-:521** re-verified by `git check-ignore` THIS pass (`copy/`
  :500, `o2/` :501; `grep -c "row 18k" .gitignore` = 1).
- **Git-face VERIFY (the 18i law, SECOND straight HELD)**: d7aa42c
  reflog entry (`git reflog`, re-read THIS pass) reads plain
  **`commit:`** — NO amend, single push, origin/master == HEAD
  (`rev-list --count` both = **111**; `ls-remote origin
  refs/heads/master` = `d7aa42cef7d9…`) — the 18i rule HELD a SECOND
  STRAIGHT row (18j then 18k). The 18i orphan **69c8b6f NOT an
  ancestor of origin/master RE-PROVED THIS pass cheaply**
  (`merge-base --is-ancestor 69c8b6f origin/master` rc **1**).
- **ZERO-GATE ARTIFACTS — face ENFORCED, census UNDISTURBED**: TWO-LINEAGE
  census MEASURED at this docs pass OUTSIDE the harness too:
  `ls tools/*/gate.txt | wc -l` = **25**, md5 holders of `4826fc22…` =
  **9**, distinct md5s = **17**, `git ls-files 'tools/*/gate.txt'` =
  **1** (gre's — still the only tracked gate), gre anchor re-md5'd
  `6751d1a8…` byte-exact. misc3 added ZERO gate files: 18k = the
  **18th straight honest zero-gate face** (briefing "25/9/17 + tracked
  1" RE-MEASURED true — the census ritual itself now a briefing-true
  face for TWO straight rows). **Frozen lineage verified the
  sanctioned way** — direct md5 re-sums, frozen donors NOT chased to
  rc 0: daq3 vectors `fd1855e1` + faceA `2fb9dc45`, small4 `462f0ff6`/
  `4755d48c`, miscip `43b259ac`/`e4c47bac`, tun `2a792479`/`81602890`,
  ext `da218429`/`0fa79b53`, eth `1bd98dbb`, csum `e4baf781`, fmod
  vectors `f0fdbab`, vocab vectors `5da70e82`, witness census
  `9fad7e9d`/`be9bdd0b`/`f4afd35f`/`ea1f79f3`/`c5b498ff` — ALL
  byte-exact THIS pass (zero drift).
- **Gate chain frozen side — MEASURED not asserted**: gre rebuilt
  FRESH x2 THIS pass rc 0 BOTH (LOGS byte-ident receipts
  `row18ldocs/gre_{A,B}.log`, tail `GRE_HARNESS_OK vectors=26 faceA=5
  gate_lines=3`, gate `6751d1a8` echo re-read in log B); fmod FRESH
  rc 0 (gate `4826fc22` echo in log + `FMOD_HARNESS_OK vectors=61`);
  vocab FRESH rc 0 (`VOCAB_HARNESS_OK vectors=29`). Receipts
  `/opt/data/cache/scratch/row18ldocs/{misc3_A,misc3_B,gre_A,gre_B,fmod,vocab}.log`.
- **Rust-side anchors re-grounded THIS pass**: trio TUs **290 + 218 +
  333 = 841 L FLAT** (wc THIS pass; `src/codecs/mod.rs` pub-mod trio
  at :71/:79/:80 + doc rows :46-:48, `grep -c 'pub mod cd_'` = 27);
  the ladder post-18k face (`src/codecs/codec_api.rs`, 174 L):
  `STATIC_CODEC_EXTERN_NAMES: [&str; 34]` still at **:97** (re-sed
  THIS pass) — cd_llc **:117** / cd_user **:129** / cd_vxlan **:131**
  (sed re-read: `"cd_llc",`/`"cd_user",`/`"cd_vxlan",` — the trio
  TURNED loaded at 18k, NEVER re-touched, the 34-census NEVER moves);
  the **18l hand-off names ALREADY resident** (re-read THIS pass,
  NEVER re-touch): cd_ciscometadata **:101** / cd_erspan2 **:103** /
  cd_erspan3 **:104** / cd_fabricpath **:107** / cd_mpls **:119** /
  cd_pppencap **:122** / cd_pppoepkt **:123** / cd_transbridge
  **:127** / cd_vlan **:130**; `#[no_mangle]` honesty face:
  `grep -rn '#\[no_mangle\]' src/` = 4 hits but ALL four are
  DOC-comment text inside the 18j TUs (cd_icmp6_ip.rs :24/:239 +
  cd_icmp4_ip.rs :16/:525) — **ZERO attribute sites**, the claim
  stands at the attribute face, record the grep face precisely; the
  39-extern cc census re-counted = **39** (ground
  `src/codecs/codec_api.cc`); link externs/loads re-grepped
  ground-side THIS pass (18l hand-off, ladder NEVER touched):
  ciscometadata :43 + load :88, erspan2 :45 + load :90, erspan3 :46 +
  load :91, fabricpath :49 + load :94, mpls :61 + load :106, pppencap
  :64 + load :109, pppoepkt :65 + load :110, transbridge :69 + load
  :114, vlan :72 + load :117. llc sids pin-site re-read
  `codec_module.rs :97-:98` = `DECODE_BAD_LLC_HEADER = 131, // h:80` +
  `DECODE_BAD_LLC_OTHER = 132, // h:81` byte-true; PROTO_BIT__VXLAN
  landed face re-read `cd_vxlan.rs :42/:70` (decode_data.h:105 cite,
  ground `#define PROTO_BIT__VXLAN 0x040000` at decode_data.h :105
  re-sed'd = byte-true); hidden-table ifdef arm face re-read ground
  cd_llc.cc :190-:197 (`#ifdef BUILDING_SO / snort_plugins / #else /
  cd_llc[] / #endif / { &llc_api.base, nullptr }`) = the harness sed
  pins stand.
- **clippy-allow census (precise)**: `assertions_on_constants` allow =
  EXACTLY 1 new this row at `tests/misc3_parity_test.rs :485-:486`
  (the 1/0/0 record-census pin site). Cited precedent sites
  RE-CONFIRMED at their true homes — it is a TESTS-side precedent:
  `tests/ext_parity_test.rs :589`, `tests/small4_parity_test.rs :594`
  (the exact site the misc3 test comment cites),
  `tests/vocab_parity_test.rs :254` — NOT src/ files; `src/file_api/
  file_log.rs :870` carries only a text mention (no attribute). ZERO
  allows in the three new TUs.
- **Test math**: 573 = 565 + 8; plain `cargo test` 69 result lines
  (69 `test result` lines grep-counted), summed programmatically 573
  passed / 0 failed, FAILED/panicked grep 0, at THIS pass (receipt
  `row18ldocs/cargo_test_18ldocs.log`); 42 parity files (41 + misc3).
- **commit census + gitignore**: 111 at HEAD d7aa42c (origin 111,
  clean); `git status --porcelain` **EMPTY** (wc 0) after ALL docs-pass
  rebuilds — artifacts fully absorbed.

## PROCESS LESSONS — the 18i amend-after-push incident (rule section) + the 18j AND 18k HELD face (positive lesson)

THIS IS A RULE SECTION, NOT A FOOTNOTE. The 18i row committed a
git-face violation of the lineage's own land rule, then corrected it
in-ref; 18j AND 18k executed the rule CLEAN (single `commit:` reflog
entry, single push, no force — d7aa42c's `HEAD@{0}` re-read THIS pass
literally reads plain `commit:`); every future agent must read this
before touching a pushed commit.

**What happened at 18i (transcript timestamps, `git reflog` +
receipt-file mtimes):**
- `2026-11-21 02:10:27` — commit **69c8b6f** = row 18i lands.
- `2026-11-21 02:10:33` — `push origin master` succeeds:
  `origin/master@{1} = 69c8b6f ("update by push")`. THE PUSH CLOSED
  THE AMEND WINDOW at this moment.
- `2026-11-21 02:10:35` — `build_E.log` rc 1: the FIRST post-commit
  ritual run; a dirty-4 whitelist guard strands the EMPTY post-commit
  face (the session-start ritual runs with the row LANDED).
- `2026-11-21 02:15:37` — `build_F.log` + `build_G.log` rc 1 x2: a
  NO-PRECEDENT own-repo HEAD self-pin died after EVERY landing by
  design.
- `02:18-02:19` — guard re-ruled in the working tree: dirty face
  becomes a row-face regex (EMPTY + this row's 15 paths; fires on any
  other row's file), self-pin DROPPED with in-situ comment.
- `02:20:54` — **e6f5616 via `git commit --amend` of the
  ALREADY-PUSHED 69c8b6f** (reflog literally reads `commit (amend)`;
  payload = guard text + honesty records ONLY).
- `02:20:56` — `push --force-with-lease` REWROTE origin/master.
  69c8b6f is NOT an ancestor of current origin/master — **RE-PROVED
  AGAIN THIS (18k) pass**, `merge-base --is-ancestor` rc 1.

**Why it was wrong (even though the payload was clean):**
`--force-with-lease` makes a rewrite SAFE against clobbering others —
it does NOT make it PERMITTED. The ONE-COMMIT-PER-ROW goal NEVER
outranks push immutability. The rule applies to COMMIT OBJECTS, not
just file contents. Contrast the legal face: the 18g docs commit was
AMENDED (97104e4 -> a7c976a) but 97104e4 was NEVER pushed — a PRE-push
amend is inside the one-commit discipline; a POST-push amend is
history rewriting. The amend window closes the instant the push helper
returns success.

**The 18j + 18k HELD faces (POSITIVE lesson — the rule works twice):**
76c1c16: single `commit:` reflog, one push, origin == HEAD. d7aa42c:
same, plus the post-commit ritual survived its OWN landing at both
rows (misc3 build.sh carries the face-agnostic row-face regex + the
ground-identity re-pins cloned from daq3/miscip — the 18i
anti-patterns NEVER reintroduced at three consecutive landings). The
rule forward is tested three ways: violated once (18i, logged, never
hidden), held at 18j, held again at 18k.

**The rule forward (binding on every future row):**
1. Post-push fixes ship as a FOLLOW-UP COMMIT (own honest message,
   receipts kept), or ride the NEXT docs commit. NEVER a post-push
   amend, NEVER a force of any flavor (`--force-with-lease`
   included). ONE-COMMIT is a goal pursued BEFORE the push; push
   immutability is the hard constraint AFTER it.
2. Harness git-state guards must be FACE-AGNOSTIC: daq3 build.sh
   :660-688 (row-face regex) — cloned at 18j AND 18k — is the landed
   template; NEVER a fixed dirty-N whitelist, NEVER a harness that
   dies at its own row's post-commit face.
3. NEVER pin the working repo's own HEAD in a harness. Pin the
   IMMUTABLE ground only (misc3/miscip/daq3 ground-identity re-pins;
   NEVER re-type sha-cite line numbers — sed the landed file).
4. The rc1 faces stay as receipts and in deviations — the honesty
   record exists; only the git MECHANISM was wrong at 18i.

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript. vectors.txt is a tracked
   INPUT the build re-verifies but NEVER fabricates (18d lesson;
   FIRST-RUN-SEED then drift-then-refuse face, misc3 build.sh wc 18/19
   pins + the cmp arms; vectors md5 byte-stable across the fresh x2
   docs-pass rebuilds THIS pass).
2. **Catch gate** whenever upstream ships an embedded
   `#ifdef UNIT_TEST` block or a `test/` suite: compile it verbatim
   (`catch/snort_catch.h` -> plain-catch shim; the FRESHEST working
   shape stays at GRE: `tools/gre_harness/build.sh` :132 catch.hpp cp +
   :139 catch_main.cc heredoc + :143 CATCH_CONFIG_MAIN pin;
   TestCaseInstaller REJECTED at 18g, deviation :2928-:2939). Run it;
   record cases/assertions in `gate.txt` (the gre pattern: TRACKED
   md5 + wc + runner tail wording). NEVER gate on grep-estimated
   assertion counts (17p). Duplicate-symbol rule when gate and probe
   link the same TU (E9 face at gre). Zero-suite rows run the
   **zero-gate face** (`test ! -e gate.txt` + NO Catch symbols
   asserted IN the build + the two-lineage census loop (9/25/17-style)
   + the stageables -eq N face; a row whose witness IS the evidence
   face TRACKS the witness file — daq3/miscip/misc3 = 7 tracked faces
   each, census re-asserted every build). The 17y INVERSION lesson,
   the 18a PER-LINK corollary, the 18b PROBE-ONLY corollary, the 18d
   INVERTED-DUP face, the 18e FACE-RULE, the 18g TWO-LINEAGE
   codification, the 18h peg-vs-hook grep correction and the 18i
   git-face rules (amend window / face-agnostic guards / no own-HEAD
   pins) all stand. A fake Catch gate over a suite-zero row = the 17p
   anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced and every one gets a section
   in `KNOWN DEVIATIONS.md`. 18i-18k reinforcements: a missing
   external header is met by a MINIMAL measured graft built ONLY off
   the use-site symbol census (daq.h 33 L NEVER re-authored — rows
   RE-APPLY the tracked cp); a graft that FAILS a later consumer is
   met by a NEW face IN THE CONSUMER'S harness (graft-v2 at the misc3
   heredoc + per-link isolation + the frozen donor's OWN consumers
   re-checked green-under-the-new-face x3 — the 18k pattern), never
   trim ground C, never pure-defer an include that rides ground TUs;
   dead-in-C gates/comments transcribe LITERAL with pins (18k: the
   cc:103 SEGV chain-call cited-NEVER-faked, the six dead llc
   `#define`s token-zero prose-only, the cc:70 FIXIT-L debt comment
   pinned above the landed sp/dp observables); a witness body is never
   worth unbounded closure (18k: the 856-L sfdaq pair NEVER compiled,
   SYNTHETIC class-stub witness per the 18j cited-minimal precedent,
   the REAL SFDAQ provider home LEFT-OPEN NEVER invented).
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-index assert, ORDERED, never set-membership),
   donor pattern: `tests/misc3_parity_test.rs` (781 L, 8 tests — the
   hidden-table tripwire unit + record-census 1/0/0 pin with the cited
   point-site allow + CppUTest dialect census + the cite-line-fed-by-
   ZERO-decode face + the set_key PIN / cite-never-land 192.168
   tripwire), `tests/miscip_parity_test.rs` (636 L, 8 tests),
   `tests/daq3_parity_test.rs` (1,269 L, 8 tests), plus small4/gre/
   tun/eth/vocab/csum.
5. **Gates at EVERY commit**: `cargo test` all green (>= 573; never
   trust a summed total from a run containing FAILED; cite one face
   per pass), clippy --all-targets ZERO warnings (force relint by
   touching all .rs), `vectors.txt` md5 stable across >= 2 clean
   rebuilds (misc3 FRESH x2 logs byte-ident THIS pass), harness
   `.gitignore` block added (mirror siblings) and verified with
   `git check-ignore` BEFORE staging (the misc3 block is
   .gitignore:494-:521, landed inside code commit d7aa42c). Then
   commit + push, insert the plan row (grep-guard: count must be 0
   before insert), append deviations (one grep-guarded append) — the
   18b-18k variant: BOTH ship inside the code commit, then the docs
   pass VERIFY-greps them (count == 1 each) and still re-measures
   every load-bearing claim. Refresh NEXT.md (FRESH rewrite),
   commit+push docs. ONE code commit + ONE docs commit, each pushed
   ONCE, NEVER amended, NEVER force-pushed (the 18j AND 18k faces
   prove the cadence works clean). Wiki: status row + deviations
   section + stats line at the WIKI phase — queue measured THIS pass:
   ff9f931 = 18j LANDED on the REMOTE; the 18k trio PREPARED but
   UNCOMMITTED in the worktree (finish + push at the wiki phase,
   re-measure stats LIVE).

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote. A push is ONE-WAY (see PROCESS LESSONS): after it returns rc 0, fixes ride follow-up commits, never `--amend`/`--force-with-lease`.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. 17s/18b-18k do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH; nm pin fmod build.sh:961). Row-TU lua-seam assert carried every build since 18d.
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum/vocab/eth/ext/tun/gre build + the 18j/18k misc/test dialect census add_cpputest x3: `ip/test/` holds ONLY checksum_test.cc and `misc/test/` ONLY geneve/gtp/teredo (ls re-run THIS pass) — both CppUTest dialect ONLY). Upstream CppUTest suites can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp `74ef54e8` + shim) runs natively — the cd_gre gate ran REAL at 18g. **ip/checksum.h DONOR-RESIDENT** (`b43628f3` ground face, find-1 in the misc3 copy re-measured THIS pass): pgm rode it at 18h, the 18i trio rode it too. `log/text_log.h` `3e827113` resident via the tun lineage. **`log/log_text.h` find-1 in the misc3 copy** (ground 64 L; trans_bridge's row rides it — re-measured THIS pass).
- **`#include <daq.h>` IS A LANDED-ONCE GRAFT (family EXTENDED at 18k — THREE daq faces, NEVER confuse)**: (1) **`daq.h`** 33 L md5 `73fdbc39…` — daq3 home, commit-tracked, tools-wide `find tools -name daq.h` = **EXACTLY-1** re-measured THIS pass; ground tree + host have NO daq.h (`find /opt/data/snort3-src -name 'daq.h'` = 0) — riders RE-APPLY the tracked cp, NEVER re-author; `ip/cd_{ipv4,ipv6,tcp}.cc` include it at :25 (re-grepped THIS pass) and `link/cd_vlan.cc` at :29 — but the 33 L face carries daq_msg_get_data/_meta (x2 grep hits) and **ZERO `daq_msg_get_pkthdr`/`DAQ_PktHdr_t`/`DAQ_PKT_FLAG_IGNORE_VLAN`** (grep 0/0/0 measured THIS pass) — cd_vlan calls exactly those THREE (:141/:141/:142) => the vlan row needs a graft-EXTENSION measure, PLAN-0, NEVER pre-typed. (2) **`daq_common.h` v16** 16 L md5 `f683749c…` — fmod home (re-md5'd byte-ident THIS pass), the cd_user.cc :24 include face sed-pinned by misc3 build.sh :155-:156 as the DONOR face. (3) **graft-v2 `daq_common.h`** — the misc3 build.sh `EOFGRAFT` heredoc face (`typedef const void* DAQ_Msg_h` FLIP + 6 SDK typedefs + DAQ_SUCCESS; on-disk copy md5 `fead0027…` regenerated every build; the fmod 16 L v16 FAILS cd_user.cc:101 — `E4_cd_user_v1.txt` rehearsed in-tree EVERY build, per-link isolation: v2 NEVER lands as a second tracked cp and NEVER touches fmod/daq3; the daq3 ip trio green-under-v2 rc0 x3 inside misc3 proves the flip never breaks its consumers the silent way). NEVER confuse these with `daqs/daq_user.h` (54 L, tracked misc3 cp `1d2e2b9c`), `src/pub_sub/daq_message_event.h`, or `packet_io/sfdaq*.h` (72/105 L tracked cps, `2e272d2d`/`9497f394`). The daq fns (`daq_msg_get_data`/`_meta`, SYNTHETIC bodies) + `sfdaq_query_usr_pci` (witness-mirror fn) stay the lineage's graft/witness-borne faces; raw.daq_msg PROVENANCE stays OPEN (17d ruling; framework/codec.rs :9 Rust face; row 20 cites the real SDK). vocab `daq_dlt.h` 5 L graft unchanged (find-1 in misc3 copy — vlan/ipv4/ipv6 include it too).
- **Hidden BUILDING_SO table face is codecs-FAMILY-wide, NOT misc-specific**: 18j pair x2 + 18k trio x3 landed; `grep -c BUILDING_SO` over the FULL link tail 9 = **1 x9** measured THIS pass (sed anchors: mpls :385 / vlan :231 / erspan2 :139 / erspan3 :141 / fabricpath :181 / ciscometadata :230 / pppoe :236 / trans_bridge :152 / ppp_encap :169 — the `cd_pppoepkt[]`/`cd_transbridge[]`/`cd_pppencap[]` DRIFT table names, see the 18l section); every codecs sed census MUST pin the ifdef arms; the string `cd_<name>[]` NEVER exists in a .so face (`snort_plugins` 1/1 each; the misc trio's :190-:197 arm face re-read ground-side THIS pass).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 + 18d-18k replay mirrored Rust-side: R6 var-first census at the 18 misc3 probe_dec arms, `printf.*->decode` 0).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY. Since 18a `file_trace` has its REAL def on BOTH sides.
- Frozen-donor build.sh rc-1 face (the 18g drift codified): tun/eth/ext die at their point-in-time `-eq 24` gate.txt ls-asserts (tun :334, eth :598, ext :320) since gre added the 25th gate — BY DESIGN, NEVER edit frozen scripts; verify their frozen face by DIRECT vectors md5 re-sums (re-done THIS pass: tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`, eth `1bd98dbb` — all byte-exact). small4/daq3/miscip are frozen-lineage TOO (direct-md5 ONLY).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/misc3_harness/` — **THE donor for row 18l (lineage head, ZERO-gate + graft-v2 heredoc + tracked SFDAQ-pair witness + hidden-table census x3 + 111-tree)**: exactly **7** tracked files (build.sh 775 L `1b9978d6…`, PLAN.md 118 L, probe.cc 53 L, probe_dec.cc 115 L, vectors.txt 18 L `e75f7385…`, vectors_faceA.txt 19 L `fe1189c6…`, witness_trio.cc 35 L `ef50cd2f…`); NO gate.txt, NO catch_main. Self-checks re-run THIS pass at BOTH fresh rebuilds (rc 0 logs byte-ident): ground md5 x3 + wc x3 + the **-eq 498** sum pin :50; combined gate grep 0 x3 + misc/test dialect STOP-flag census NEGATIVE + trio-include grep 0 x3; hidden-table sed pins x3 (arms :193/:127/:161, feeds :196/:130/:164); 39-extern cc census :111; ladder `[&str; 34]` :97 sed-pin at :113; daq.h tools-wide find-1 + graft-v2 second-landing census honest; per-include residency census + fresh candidates find-0; E4 flipped walls EVERY build (each fresh cp -> ONLY cd_user DIES cc:26/:28/:29; codec_module.h -> ONLY cd_llc; active.h -> ONLY cd_vxlan; daq.h -> ip trio x3 DIE + misc trio x3 SURVIVE = the daq_common.h face; restored rc0 x3; the v16-rc1 face `E4_cd_user_v1.txt` re-armed as a grep-assert); donor find-count **-eq 105** live-head-face -> mid **-eq 112** -> post **-eq 111** (all asserted MEASURED — independently re-found OUTSIDE the harness THIS pass = 111 non-.o); nm per-TU U echo `22/10/13 union 28 union-mangled 33 (tb 0/1/0)`; staged L1 undefined-DISTINCT-EXACTLY-2 -> +witness GREEN, own-new T EXACTLY-2; get_proto_name row census 0 (donor-inherited cite NEVER linked); stageables -eq 7 face; vectors wc pins 18/19 + O0==O2 cmp arms; frozen census loop `9/25/17 + tracked-1`; **BACKBONE-10** receipt census (`build.sh :712/:774`: gate.txt ls-25 asserts EXTERNAL + the `backbone10.txt` receipt face — 8->10 pin post-row: +miscip vectors pair +witness_miscip at 18j, +witness_trio + regen witness_conf `4dd91018`; EXACTLY 10 md5 lines re-counted THIS pass; the receipt is gitignored-and-regenerated, the MOVEMENT is honest, rows NEVER rewritten); row-face dirty guard regex (the 18i template clone, survived its own landing). **Copy tree HEAD face: 111 post-strip** (105 miscip post-strip + daqs/daq_user.h + packet_io/sfdaq{,_instance}.h + 3 misc TUs; daq.h REUSE NEVER stays; graft-v2 daq_common.h regenerated EVERY build — the additive file set for 18l's fresh-cp measures).
- `tools/miscip_harness/` — the 18j ancestor (NOW frozen-lineage face; direct md5 sanctioned, re-done THIS pass `43b259ac`/`e4c47bac`/witness `c5b498ff` byte-exact): exactly 7 tracked files (build.sh 606 L `c7e55448`, probe 43 L, probe_dec 92 L, witness_miscip.cc 27 L); the 105 post-strip tree face = misc3's donor; the hidden-table + witness-mirror precedents live HERE; **tcp.h 211 L `a7ac7b82` BANKED for the cd_tcp row (find-1 in the misc3 copy re-measured THIS pass)**.
- `tools/daq3_harness/` — the 18i ancestor (frozen-lineage face; direct md5 `fd1855e1`/`2fb9dc45` byte-exact THIS pass): exactly 7 tracked files (build.sh 695 L, witness_daq.cc 54 L `e0166b02`); THE daq.h graft home (copy/daq.h 33 L `73fdbc39` re-md5'd THIS pass; never re-authored); the row-face dirty-guard template :660-:688.
- `tools/small4_harness/` — the 18h donor (frozen-lineage face): 6 tracked files (build.sh 453 L; probe 46 L vectors face `462f0ff6`/`4755d48c` direct re-summed); copy tree 96 face; ZERO-gate face + first FIRST-RUN-SEED drift-refuse.
- `tools/gre_harness/` — **THE gate-shape donor (18g; kept for ANY row with real Catch/Catch-suite material)**: exactly 8 tracked files, gate.txt 3 L md5 `6751d1a8` TRACKED (tail `All tests passed (1 assertion in 1 test case)`, pins :378-:382), vectors `41bd7d1b` 26 L + faceA `783649440d` 5 L, build.sh 412 L, anchors :43-:49, catch shape :132/:139/:143, E9 dup flipped-assert, rfind+cut-to-EOF excision, census loop :401-:404. Rebuilt FRESH x2 THIS pass, rc 0, logs byte-ident. ALSO the tunnel-bypass witness carry face: build.sh :19 (the ONE `tunnel_bypass_enabled` witness rides from tun), :170 `-ge 1` grep on `tun_harness/witness_18f.cc`, :298 exactly-ONE-U-line census — the 18k vxlan row cloned THAT; the 18l mpls row (cd_mpls.cc :205-:206 HOOK, TUNNEL_MPLS = **0x80 snort_config.h :126** re-sed'd THIS pass) clones it again if (a3) moves mpls up.
- `tools/tun_harness/` — 18f ancestor (7 tracked files; `-eq 24` line dies by design): vectors `2a792479` + `81602890`, witness_18f.cc `ea1f79f3` (**the `SnortConfig::tunnel_bypass_enabled` witness def at witness_18f.cc:16** — the banked bypass-hook witness; gre AND misc3 ride the SAME; md5 re-verified THIS pass). Direct-md5 face ONLY.
- `tools/ext_harness/` — 18e ancestor (7 tracked files): DUAL faces `da218429` + `0fa79b53` zero drift re-summed THIS pass. `-eq 24` face dead by design.
- `tools/eth_harness/` — 18d ancestor (5 tracked files): stubs_18d.cc `f4afd35f` RETIRED marker; vectors `1bd98dbb`.
- `tools/vocab_harness/` — the 18c ancestor (rebuilt FRESH THIS pass rc 0 `VOCAB_HARNESS_OK vectors=29`): witness_stubs.cc `9fad7e9d` re-md5'd — the 3 STUB tables cd_ipv4 :11 / cd_ipv6 :12 / cd_tcp :13 (+ cd_hopopts RETIRED face) frozen by vectors:25-:28 — **the heavyweight trio's ONLY retirement landmine lives at :11-:13**; **ZERO link-family names in that witness face OR codec stubs.cc (grep = 0 re-run THIS pass => the link rows carry ZERO stub retirements)**; vectors `5da70e82` stable; `daq_dlt.h` graft home.
- `tools/fmod_harness/` — the 18a donor & **FROZEN gate-lineage source** (rebuilt FRESH THIS pass rc 0 `FMOD_HARNESS_OK vectors=61`, gate `4826fc22` echo in log, vectors `f0fdbab`): cp braces + objs loop carry the FULL file_api closure; libluajit.a BY PATH, nm pin :961; catch-recipe carry :249/:270; **daq_common.h v16 16 L graft home `f683749c…`** (byte-ident re-md5'd THIS pass; the misc3 graft-v2 heredoc NEVER touches it — sed-pinned at misc3 build.sh :155-:156).
- `tools/csum_harness/` — row 18b, the probe-only origin: ground-header md5 pin :37, E4 wall receipt :67-:70, nm ZERO-text-symbols :79-:80, O0==O2 :116, vectors 16L md5 `e4baf781` re-md5'd THIS pass.
- `tools/flog_harness/` (17z): 50L `b260ec6a`. `tools/fsvc_harness/` (17y): 64L `54864705`. `tools/fpolicy_harness/` (17x): 27L `b989a8d5`. `tools/finspect_harness/` (17w): 103L `3cbd009e`. `tools/fcapi_harness/` (17v): 21L `a953a501`. `tools/fconf_harness/` (17u): 20L `65968e1c`. `tools/fcshare_harness/` (17t): 25L `03d43c14`. `tools/fcap_harness/` (17s): 27L `0208a691`; gate `4826fc22` — frozen chain START.
- `tools/fctx_harness/` — vectors 610L `839b5566`; gate `42349372`. `tools/fflows_harness/` 146L `bd8c00af` (DO NOT touch), gate `e14626fc`. `tools/fcache_harness/` 278L `b69db310` (DO NOT touch), gate `6b3c041e`. `tools/filib_harness/` 273L `77ffd8e4` (DO NOT touch). `tools/textlog_harness/` — time() interposition precedent. `tools/rules_harness/` — hosts `copy/catch/catch.hpp` `74ef54e8`. **`tools/codec_harness/` is row 17d's harness** (stubs.cc md5 `be9bdd0b…` re-confirmed THIS pass is the FROZEN donor the E6-YES arms re-collide against) — the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.

## Next milestone — row 18l: THE LINK TAIL (misc/ is CLOSED — nothing remains; fresh-measured this 18k docs pass) — sub-trio scoping w/ decision table; the tail CANNOT land as ONE row at 1,915 L (the cadence cap sits ~2.4k/row max, 498-1,823 typical) — pick a coherent SUB-TRIO (decision below; PLAN-0 at 18l finalizes)

### The link tail face, measured THIS pass (ground `/opt/data/snort3-src/src/codecs/link` @ fe29cbe7403a READ-ONLY; `find . -maxdepth 3 -type d -name link` = EXACTLY 1 dir with .cc files = `src/codecs/link` (measured — no other link dir); copy-tree residency vs the **111-tree misc3 head**)
- **Which dirs exist + what remains**: `src/codecs/{ip,link,misc,root}` (ls THIS pass). **misc/ CLOSED**: `ls src/codecs/misc/*.cc` = 9 files, ALL landed (default/geneve/gtp/teredo/icmp4_ip/icmp6_ip at 18c/18f/18j + llc/user/vxlan at 18k). **root/ + vocab CLOSED** (codec_api/codec_module + cd_raw at 18c). **ip/**: `cd_ipv4 790 / cd_ipv6 733 / cd_tcp 839` remain (+ checksum.h landed 18b). **link/ = the tail**: 10 .cc, `cd_arp.cc 128 L` ALREADY landed (18d — src/codecs/cd_arp.rs exists, re-checked; no other link-family `cd_*.rs` exists — 12/12 candidate link TU names absent from src, measured) => **9 files / 1,915 L**: mpls **390** / vlan **236** / pppoe **243** / erspan2 **145** / erspan3 **147** / ciscometadata **235** / fabricpath **187** / trans_bridge **158** / ppp_encap **174** (wc ALL re-run THIS pass — matches the 18j-era "link tail 9 re-wc 1915" cite, zero drift).
- **Gate material ZERO x9**: combined `TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST` grep = 0 for every one of the 9 (measured); **the link dir has NO test/ subdir at all** (`find src/codecs/link -name "*test*"` = 0 — re-measured; contrast misc/test 3 files + ip/test 1 file) => pure ZERO-gate rows, **19th straight zero-gate chance**, misc3 is the clone donor.
- **Hidden BUILDING_SO tables: the census FAMILY-GENERALIZES to x9** — `grep -c BUILDING_SO` = **1 x9** (measured); table sed anchors (re-grounded THIS pass): mpls :385 / vlan :231 / erspan2 :139 / erspan3 :141 / fabricpath :181 / ciscometadata :230 + the DRIFT trio's arms **pppoe :236** / **trans_bridge :152** / **ppp_encap :169**.
- **THE TRUE-NAME DRIFT face RETURNS x3 (the row's headline candidate)**: `cd_pppoe.cc` -> table **`cd_pppoepkt[]`** :236 + NAME macros `CD_PPPOEPKT_DISC_NAME "pppoe_disc"` :115 + `CD_PPPOEPKT_SESS_NAME "pppoe_sess"` :139 (one TU, TWO api names, table name != file base); `cd_trans_bridge.cc` -> table **`cd_transbridge[]`** :152 + `CD_TRANSBRIDGE_NAME "trans_bridge"` :33 (dashed file, undashed table); `cd_ppp_encap.cc` -> table **`cd_pppencap[]`** :169 + `CD_PPPENCAP_NAME "ppp_encap"` :29 (same shape). The other six are TRUE-NAME clean (file base == table base, measured). The Rust ladder ALREADY carries the drift names — cd_pppencap **:122** / cd_pppoepkt **:123** / cd_transbridge **:127** (sed re-read THIS pass) — the rows TURN them loaded, the ladder NEVER moves (the 18k trio face is the template); Rust file-vs-table tripwires clone cd_auth/CD_AH + the 18k hidden-table units at TRIPLY scale for these three.
- **Residency vs the 111-tree head (the fresh-cp census; `find tools/misc3_harness/copy -type f -path "*/<h>"` THIS pass)**: headers the 9 files need = ALL-RESIDENT for six of nine: erspan2/:21-25, erspan3, fabricpath :21-25 (:21-:25 = config.h/codec_module.h/framework/codec.h — find 1), trans_bridge (+ log/log_text.h find 1 + protocols/eth.h find 1), ppp_encap :22-25, pppoe :21-26 — **ZERO fresh cps for pppoe/erspan2/erspan3/trans_bridge/ppp_encap/fabricpath** (config.h, codecs/codec_module.h, framework/codec.h, log/log_text.h, protocols/eth.h ALL find-1 measured). Fresh-cp census for the other three: **vlan**: `<daq.h>` :29 (graft RE-APPLY + the EXTENSION face — `daq_msg_get_pkthdr`/`DAQ_PktHdr_t`/`DAQ_PKT_FLAG_IGNORE_VLAN` all grep-0 in the 33 L face, measured; + `<daq_dlt.h>` :26 find-1 resident) + `protocols/vlan.h` :34 **50 L find-0**; **mpls**: `flow/flow.h` :26 **637 L find-0** + `utils/safec.h` :30 **42 L find-0** (the rest of config/codec_module/text_log/snort_config find-1) — AND flow.h's OWN includes carry **SIX more find-0 headers** (detection/ips_context_chain.h, flow/deferred_trust.h, flow/flow_data.h, flow/flow_stash.h, flow/flowip.h, time/clock_defs.h — find-counted vs the copy THIS pass; data_bus/decode_data/inspector/layer/sf_ip/snort_protocols/flow_key already find-1) = **mpls is THE heaviest closure row in the backlog**; **ciscometadata**: `protocols/cisco_meta_data.h` :27 **43 L find-0** (its only include = `<arpa/inet.h>` system, trivial — the ONLY one-cp closure in the tail). safec.h itself `#include <safe_mem_lib.h>/<safe_str_lib.h>` — host find = 0 (re-measured) => graft-or-witness measure AT the mpls/vlan rows, PLAN-0.
- **Ladder/externs hand-off (resident, NEVER re-touch)**: ground externs ciscometadata :43 + load :88, erspan2 :45 + :90, erspan3 :46 + :91, fabricpath :49 + :94, mpls :61 + :106, pppencap :64 + :109, pppoepkt :65 + :110, transbridge :69 + :114, vlan :72 + :117 (ALL re-grepped ground `src/codecs/codec_api.cc` THIS pass; the 39-extern census STILL = **39** re-counted); Rust ladder :101/:103/:104/:107/:119/:122/:123/:127/:130 resident (re-read above) — NO unloaded-pin test names the link family (the trio/pair pins are row-local); completeness = each row test's own hidden-table tripwire + the 34-census pin.
- **Landmine posture ZERO across the tail**: `cd_mpls|cd_vlan|cd_ppp*|cd_erspan*|cd_fabricpath|cd_ciscometadata|cd_transbridge` grep = **0** in vocab witness_stubs.cc AND codec_harness stubs.cc (measured THIS pass) — the ONLY stub-retirement family stays the heavyweight :11-:13 trio; the link rows NEVER touch it.
- **Sids COMPLETELY resident — ZERO new DECODE_* constants**: union of `DECODE_*` tokens over the 9 files = **19 distinct** (receipt `/opt/data/cache/scratch/row18ldocs/link_sids.txt`; MPLS 7 + PPPOE 2 + VLAN 1 + CISCO_META 4 + ERSPAN 3 + FPATH 1 + GRE_TRANS 1) — **19/19 already in `src/codecs/codec_module.rs`** (sample: `DECODE_BAD_PPPOE_DISC = 120, // h:78` at :95, `DECODE_ERSPAN_HDR_VERSION_MISMATCH = 462, // h:215` at :220, `DECODE_BAD_PPPOE_SESS = 479, // h:232` at :237) — every link row ports RuleMap TABLES onto resident sids (RuleMap grep census per file: mpls/vlan/ciscometadata/erspan2/erspan3/fabricpath 2 each, pppoe 5, trans_bridge 0, ppp_encap 0) => ZERO new constants anywhere.
- **tunnel_bypass axis (the 18k-vxlan clone rides again)**: ONLY cd_mpls carries the HOOK — :205-:206 `codec.conf->tunnel_bypass_enabled(TUNNEL_MPLS)` (grep tunnel_bypass over the 9 = 2 lines, one file, measured); `TUNNEL_MPLS = 0x80` at **snort_config.h :126** (enum block sed re-read THIS pass: 6IN6 0x20 :124 / GRE 0x40 :125 / MPLS 0x80 :126 / VXLAN 0x100 :127 / GENEVE 0x200 :128). Clone the witness_18f carry + exactly-ONE-U-line census (gre :19/:170/:298 AND misc3 faces); Rust bypass-param seam FULLY landed (cd_geneve.rs :300/:361-:362 family, field framework/codec.rs :236/:258) — ZERO new bypass witnesses expected, MEASURE at PLAN-0.
- **Vocab heads (row-scoped, dup-vs-import ruling per the banked cd_icmp6.rs:179-:183 face)**: MPLS/VLAN/ERSPAN/FABRIC_PATH protocol-id + PROTO_BIT__* faces re-check per row at PLAN-0 (MEASURE landed-vs-land: protocol_ids.h values already landed row-scoped for the tunnel family; framework `protocol_id::` members IMPORT, codec-scoped idups stay file-local, NEVER air); `CODEC_NON_IP_TUNNEL 0x0200` already landed framework/codec.rs :51 — import for the tunnel-ish link faces (mpls/vlan ride the family).

### 18l alternatives — honest comparison (ALL measured THIS pass; sizes from the re-wc sweep)
|| option | size | fresh-cp / risk face | decision weight |
|---|---|---|---|
| **(a1) link CHEAP SUB-TRIO: cd_erspan2 145 + cd_erspan3 147 + cd_trans_bridge 158** | **450 L** (wc cites THIS pass) | **ZERO fresh cps x3 (all includes find-1 vs the 111 head, measured)** + ZERO gate + ZERO landmine + ZERO new sids + ZERO bypass axis (none of the three touches tunnel_bypass) + 1 shared sid (VERSION_MISMATCH 462 in BOTH erspans + the trans_bridge GRE_TRANS sid resident) + the erspan2/3 near-sibling pair gives the FIRST same-family sibling-contrast face (erspan3 = flow-version/word0/word1 split vs erspan2) | **cheapest tree delta + coherent family story (the erspan pair + its IEEE 802.1br Q-in-Q sibling trans_bridge); TRUE-NAME clean for the erspans with trans_bridge's cd_transbridge DRIFT as the tripwire headline baked right in** |
| (a2) link cheap TRIO-B: cd_erspan2 145 + cd_erspan3 147 + cd_fabricpath 187 | 479 L | ZERO fresh cps x3 (measured), same zero-risk face; NO drift headline; fabricpath rides the same resident sids | same class, slightly bigger, headline-poor vs (a1); swap-in if a1 trips |
| (a3) the DRIFT trio: cd_pppoe 243 + cd_trans_bridge 158 + cd_ppp_encap 174 | **575 L** | **ZERO fresh cps for ALL THREE (measured!)** + THE 3-for-3 TRUE-NAME DRIFT headline (pppoepkt/transbridge/pppencap vs their file bases, a whole-subrow triple at once, pppoe double-name :115/:139) + pppoe 5 RuleMap rows (the tail's richest rules face, all resident) | THE headline-maximal cheap option; a coherent "PPP+Q-in-Q plumbing drift" story; slightly above (a1) size; strongest tripwire story |
| (a4) ciscometadata + ppp_encap + fabricpath (or a 4th sub-trio incl ciscometadata) | 235+174+187 = **596 L** | ciscometadata = the ONLY one-cp closure (cisco_meta_data.h 43 L, `<arpa/inet.h>`-only, trivial); mixed rules 2/0/2 | middling; keep ciscometadata for a MEDIUM sub-row paired with vlan (b3) |
| (b1) heavyweight trio: ipv4 790 + ipv6 733 + tcp 839 | **2,362 L** (wc re-run THIS pass, zero drift vs cite) | daq.h RE-APPLY x3 (:25 re-grepped, tracked cp NEVER re-authored) + **FRESH-cp census find-0 x7**: parser/parse_ip.h (x3), sfip/sf_ipvar.h (x3), protocols/ipv4_options.h, protocols/tcp_options.h, stream/stream.h, utils/util.h find-**1** (resident!), utils/rnd.h... (the ip/ trio's includes dumped THIS pass — 5-6 genuinely fresh headers incl the parser/sfip/stream family, each with its OWN closure risk unmeasured) + THE ONLY stub retirements witness_stubs :11-:13 (per-LINK, E6 inverted, vectors:25-:28 face MOVES) + likely 2-3 commit SPLIT | plan order says NEXT = heavyweights, BUT the fresh-cp census (5-6 headers incl stream/stream.h + parser/ + sfip/ families, never-before-measured) is the tail's HEAVIEST closure risk + the ONLY landmine — defer until the link rows bank residency |
| (b2) heavyweights SPLIT solo: cd_tcp 839 ALONE (tcp.h banked a7ac7b82 + tcp_options fresh 1-cp + stream/stream.h + parser/sfip riders) | 839 L | smaller bite of b1; retirement trio stays UNTOUCHED until the ipv4/ipv6 legs land = LONGER stub-table window (the landmine persists 2+ rows) | honest option; but three sub-commits splitting the retirement family across rows = per-LINK corollary churn; acceptable only if b1 fully fails at PLAN-0 |
| (b3) link HEAVY sub-trio (vlan + ciscometadata + mpls) | 236+235+390 = **861 L** | vlan = daq.h RE-APPLY + graft-**EXTENSION** (three grep-0 face-sets measured) + vlan.h 50 L; mpls = flow.h 637 L + flow.h's 6 find-0 sub-headers + safec.h + host safe_*_lib ABSENT = the SINGLE HEAVIEST closure in the backlog; ciscometadata 1 trivial cp; mpls ALSO the only bypass-hook file (witness_18f clone) | the tail's hard third — schedule AFTER a1/a3; mpls LAST unless split |
| (c) tail-first order: 18l = (a1), 18m = (a3), 18n = (a4/b3), heavyweights AFTER the whole tail | 450 then 575 ... | every link row rides pure residency at ZERO fresh cps; the heavyweight census + the stub retirement land in ONE late consolidated decision with the max donor face banked | **this pass's RECOMMENDED sequence**: cheapest-first within row 18's own tail-order precedent (18h codified "tail-order call"), AND it defers the backlog's two heaviest measured risks (mpls closure, b1 closure+landmine) instead of front-loading them |
| (d) detour `src/main/thread_config.cc` | **920 L** (wc re-run THIS pass) | **14** `TEST_CASE` grep-counted THIS pass (matches the "920/14 fallback" cite EXACTLY — briefing true, measured); path face re-grounded: `src/daqs/thread_config.cc` NE-VER exists — `find . -iname '*thread_config*'` = `src/main/{thread_config.cc,thread_config.h}` ONLY; needs GRE gate shape + hwloc witness ladder (17l) + eth excision carry | Fallback ONLY if row 18 stalls (18a/18c/18d/18f/18h ruling — re-affirmed); breaks codec continuity + donor chain (a C++-gate row mid-codecs = the gate-lineage churn) |

**Decision (this pass's measured recommendation; PLAN-0 at 18l still owns the final call)**: **(c)
sequence starting with (a1) erspan2+erspan3+trans_bridge (450 L)**.
Rationale, all cites above: (i) cheapest coherent sub-unit in the
whole backlog — 450 L vs the 498-L trio precedent at ZERO fresh cps
measured vs the 111 head (the six-file zero-cp census); (ii) plan
continuity — it IS the plan's own link tail ("Thereafter" order),
tail-order-cheapest-first per the 18h precedent, misc/ now CLOSED;
(iii) the sibling-pair story (erspan2 vs erspan3 deltas = the richest
vectors face per byte at the cheapest sizes) + trans_bridge carries
the cd_transbridge table DRIFT + the shared VERSION_MISMATCH 462
cross-file pin; (iv) risk-minimal: it defers BOTH heavy measured
risks — 920-L mpls closure and the b1 heavyweight census +
stub-retirement — to rows where the donor chain is even more mature.
(a3) lands the drift trio THIRD (18m). If PLAN-0 wants the drift
headline EARliest, (a3) at 18l is the size-honest swap — its ZERO-cp
face measures equal-cheap. NEVER pre-decide beyond THIS pass's
measurement: fresh-cp counts re-measured at the row, E4 walls flipped,
landmine grep re-run.

### Rules forward from 18k
- **Git-face rules (the 18i law, HELD twice — do NOT be the third test)**: ONE commit +
  ONE push each; post-push fixups = follow-up commit; face-agnostic
  guard regex (misc3 build.sh clone of daq3 :660-:688); NO own-HEAD
  pins. d7aa42c's plain `commit:` reflog re-read THIS pass.
- The two-lineage census (**25 holders / 9 x 4826fc22 / 17 distinct —
  MEASURED direct THIS pass; `git ls-files 'tools/*/gate.txt'` = 1**)
  is the LIVE face; NEVER re-pin the arithmetic without measuring THAT
  pass (17p). The BACKBONE-10 receipt face (10 md5 lines, 8->10 pin
  logged in deviations) MOVES only when the backbone MOVES — regenerate
  the receipt every build, NEVER re-type the count. 18l clones the
  misc3 ZERO-gate face + its census loop.
- 18l rows are ZERO-gate material (0 x9 above) -> probe-only harness
  clones the MISCP3 pattern (lineage head) on the **111 post-strip**
  copy tree (add ONLY what PLAN-0 measures fresh — for (a1): ZERO
  fresh cps is a MEASURED face, re-derive it with find-counts at the
  row build, NEVER pre-assume the mid/post counts). A rider daq.h
  RE-APPLY (vlan row, heavyweights) rides the TRACKED daq3 graft +
  keeps the second-landing census honest (misc3 tripwire wording =
  template); the graft-EXTENSION face at vlan (daq_msg_get_pkthdr
  trio, grep-0 measured THIS pass) = a PLAN-0 graft-or-witness call
  built off THAT census only, NEVER pre-decided.
- A row that DOES ship real Catch material (thread_config fallback,
  row-19 detection) clones the GRE gate shape: shim passthrough +
  catch_main heredoc + TRACKED gate.txt md5/wc/tail-wording pin +
  rfind/cut-to-EOF excision + E9 dup flipped-assert.
- TRUE-NAME DRIFT rule at peak value at 18l: sed the TABLE
  (`const BaseApi\* \w+\[\]`) EVERY build — link arms :385/:231/:139/
  :141/:181/:230/:236/:152/:169 measured — and the drift trio
  (pppoepkt/transbridge/pppencap, `:236`/`:152`/`:169`) gets per-TU
  file-vs-table tripwire tests (the cd_auth + cd_icmp6/ipv6_api +
  18k hidden-table precedents). Scoping greps pin SYMBOLS not
  substrings (the 18h peg-vs-hook lesson; 18l pins: tunnel_bypass
  HOOK at mpls :205-:206 ONLY in the tail, TUNNEL_MPLS 0x80 at
  snort_config.h :126).

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — find+wc sweeps re-run THIS docs pass, zero drift vs the 18j face)
- After the link tail lands (18l+ per the decision above): the ip/
  heavyweights ipv4 **790** / ipv6 **733** / tcp **839** (wc re-run
  THIS pass) close row 18 — they carry `#include <daq.h>` :25 (the
  graft banked) + the ONLY witness-stub retirements vocab
  witness_stubs.cc :11-:13 (cd_ipv4/cd_ipv6/cd_tcp -> REAL, PER-LINK,
  E6 inverted + 3-face census) + the stream/stream.h + parser/
  parse_ip.h + sfip/sf_ipvar.h + {ipv4,tcp}_options.h fresh-HDR
  closure family (find-0 x5 measured THIS pass vs the 111 head —
  their OWN closure is UNMEASURED beyond find-0: that census is THAT
  row's PLAN-0 headline); tcp.h rides BANKED (a7ac7b82).
- The 39-extern census + the STATIC_CODEC_EXTERN_NAMES tripwire give
  every row its completeness checklist (ALL queue names ALREADY
  resident codec_api.rs :97-:131 — rows only ADD real TUs, NEVER
  touch codec_api.rs).

## Backlog (plan rows)
- 17z through 18k: DONE — wiki trios LANDED through **18j (ff9f931**,
  verified THIS pass: `git grep 'row 18j' HEAD` face present, wiki
  remote == ff9f931); the **18k trio PREPARED but UNCOMMITTED** in the
  wiki worktree (`M Porting-status.md` rows :101/:113 + `??
  dev_block_18k.txt` 115 L, deviations wiki file grep '18k' = **0**)
  — finish + push it at the wiki phase.
- 18k: **DONE (d7aa42c — 15 files +2,906/-0 live face, ZERO message
  drift THIS pass; single reflog `commit:`, single push, origin ==
  HEAD = the no-amend rule HELD SECOND STRAIGHT)** — codecs misc
  leftover trio, THE graft-v2 daq.h-REUSE row: `misc/cd_{llc,vxlan,
  user}.cc` 198+133+167 = **498 L** literal -> `src/codecs/{cd_llc,
  cd_vxlan,cd_user}.rs` 290+218+333 = **841 L FLAT** + mod.rs 3
  pub-mod ONLY outside; `tools/misc3_harness` NOW LINEAGE HEAD
  (exactly **7** tracked files incl tracked witness_trio.cc `ef50cd2f`
  = the SYNTHETIC SFDAQ pair; ZERO-gate face ENFORCED; two-lineage
  census **UNDISTURBED MEASURED THIS pass: 25 / 9 x `4826fc22` / 17
  distinct**, backbone receipt **8->10** face `backbone10.txt`);
  graft-v2 = DAQ_Msg_h const-`void*` FLIP + 6 SDK typedefs as the
  build.sh `EOFGRAFT` heredoc ONLY (fmod v16 `f683749c` frozen face
  RE-MD5'd intact; daq.h 33 L `73fdbc39` REUSE cp NEVER a second
  graft, STRIPPED end-of-build, tools-wide find-1 RE-MEASURED);
  witness delta MEASURED **+2** (staged-L1 undefined-DISTINCT
  EXACTLY-2: SFDAQ::get_local_instance + SFDAQInstance::ioctl — the
  856 L packet_io/{sfdaq,sfdaq_instance}.cc NEVER compiled,
  face-agnostic; the cc:103 ground-SEGV cite line + ioctl-fail/!pci
  cited-never-armed; SFDAQ provider home LEFT-OPEN NEVER invented);
  copy tree 105 donor post-strip + 3 fresh cps = **112 mid -> 111
  POST-STRIP** (independent find re-run THIS pass = 111); the E4
  daq.h wall flipped IN-TREE (ip trio x3 DIE + misc trio x3 SURVIVE =
  the daq_common.h face); vectors DEC 18 L `e75f7385…` + FACE-A 19 L
  `fe1189c6…` IMMUTABLE, FRESH x2 rc 0 logs **byte-ident THIS pass**;
  `tests/misc3_parity_test.rs` 781 L 8 tests = 18/18 + 19/19 ORDERED
  + hidden-table/mod_ctor-1-0-0/dialect/arms/hook-dual-face/witness-
  mirror units; mod_ctor **1/0/0** census (llc REAL LlcModule vs the
  nullptr pairs — the 18i hand-off honored); set_key dotted quads
  cite-only / sp12345+dp54321 observable PIN; six dead llc defines
  token-zero (grep-count 1 x6 RE-measured by exact token THIS pass);
  suite **573 / 0** THIS pass (69 result lines); clippy forced relint
  0 (EXACTLY 1 assertions_on_constants allow at the test pin site,
  ext/small4 test-side precedent RE-CITED at the true homes); plan row
  (PORTING_PLAN.md:90) + deviations (**:3522-:3636 = 115 L / 7
  bullets**) VERIFY-GREPED count 1 each; ritual survived its own
  landing. **Wiki trio for 18k: PREPARED-IN-WORKTREE UNCOMMITTED —
  finish at the WIKI phase** (see the measured face above).
- 18: codecs — 18b-18k DONE; 18l = link tail sub-trio (decision
  table + THIS pass's (c)-starts-(a1) recommendation above; the link
  census measured FRESH vs the 111 head; PLAN-0 finalizes (a)/(b)
  ordering at the row).
- 19: detection option engines (tree face re-stands from prior passes:
  52 .h+.cc files, 14,533 L; ~47 real Catch TEST_CASE faces — the GRE
  gate shape banked); 20: packet_io / DAQ (AF_PACKET via libc; the 17d
  RawData/daq_msg deferral + the daq graft families close HERE — the
  18i graft + witnesses, the 18j get_proto_name provider queue, the
  18k SFDAQ seam + graft-v2 face, and the vlan graft-EXTENSION all
  cite row 20's real SDK face); 21: main CLI + `snort -q -c`
  end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
   (status MUST be EMPTY; NEVER amend/force anything — the 69c8b6f
   orphan face: if it EVER reappears as an ancestor something is
   WRONG, it must stay merge-base rc 1 against origin/master — re-
   proved rc 1 at the 18j AND 18k docs passes).
2. `cd tools/misc3_harness && bash build.sh` **x2** -> `MISC3_HARNESS_OK
   vectors=18 faceA=19 gates=0` + vectors `e75f7385…` / FACE-A
   `fe1189c6…` md5 pins byte-ident across BOTH fresh runs (LOGS cmp
   byte-ident) + the E4 stripped-tree arms + the v16-rc1
   `E4_cd_user_v1.txt` arm + staged-L1 undefined-EXACTLY-2 echo + the
   frozen census echo `9/25 holders of 4826fc22, 17 distinct` + the
   BACKBONE-10 receipt echo + the nm census echo `llc=22 vxlan=10
   user=13 union=28 (tunnel_bypass 0/1/0)` + the mid-112/post-111
   find-count echo. `cd tools/gre_harness && bash build.sh` x2 for
   the GATE anchor (`GRE_HARNESS_OK vectors=26 faceA=5 gate_lines=3`,
   gate `6751d1a8`, tail `1 assertion in 1 test case`). Rebuild
   `tools/fmod_harness` for the FROZEN-chain byte-ident echo (rc 0,
   gate `4826fc22`, vectors `f0fdbab`) AND `tools/vocab_harness`
   (rc 0, `VOCAB_HARNESS_OK vectors=29`). Verify the frozen lineage by
   DIRECT md5s (misc3 `e75f7385`/`fe1189c6`, miscip/daq3 `43b259ac`/
   `e4c47bac` + `fd1855e1`/`2fb9dc45`, small4 `462f0ff6`/`4755d48c`,
   tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`, eth
   `1bd98dbb`, csum `e4baf781`, witness census `9fad7e9d`/`be9bdd0b`/
   `f4afd35f`/`ea1f79f3` + regen witness_conf `4dd91018` + witness_
   trio `ef50cd2f`; daq3/tun/eth/ext/small4/miscip NO LONGER chased to
   rc 0 — by-design drift faces — NEVER edit frozen scripts; fmod +
   gre + misc3 + vocab ARE the FRESH-build set now).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test`
   (zero FAILED; >= 573) + clippy 0 -> `.gitignore` block +
   `git check-ignore` -> commit+push (**ONE push, then done — fixes
   ride follow-up commits**; verify `git ls-remote` matches HEAD
   BEFORE any further commit) -> plan row (grep-guard) -> deviations
   append (grep-guard; 18b-18k variant: verify-grep if shipped with
   the code commit) -> refresh THIS file -> commit+push docs -> wiki
   (status row + deviations + stats line — queue: the PREPARED-
   UNCOMMITTED 18k trio FIRST, then any newer row that has landed).
