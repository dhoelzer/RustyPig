# NEXT.md — takeover context & plan (2026-11-21, post-18j: misc icmp-IP pair landed; donor = miscip_harness, ZERO-gate head + THE hidden-BUILDING_SO-table census + tracked witness face)

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

Current state (measured at this 18j verify-mode docs pass): plan rows
1–18j DONE. **109 commits at HEAD 76c1c16** (`git rev-list --count
HEAD` THIS pass; this docs commit lands as the **110th**). **565 tests
green / 0 FAILED** (full `cargo test` re-run AT THIS docs pass: summed
`test result` lines programmatically = 565 passed / 0 failed over 68
result lines; 565 = 557 at 18i + 8 `tests/miscip_parity_test.rs`
(wc 636 L, `grep -c '#\[test\]'` = 8 re-measured THIS pass); the two
new TUs `src/codecs/{cd_icmp4_ip,cd_icmp6_ip}.rs` 529 + 241 = **770 L**
carry ZERO in-crate `#[test]` (grep 0/0 re-run THIS pass); `cargo
clippy --all-targets` **0 warnings** (forced relint THIS pass: touched
every .rs, `Finished` line, `grep -c '^warning'` = 0), 51,350 lines
Rust across 150 `src/*.rs` files (`find src -name '*.rs' -exec wc -l {}
+` THIS pass), 41 `tests/*_parity_test.rs` whole-transcript replay
tests, 431 tracked files (`git ls-files | wc -l`), 48 `tools/*_harness`
dirs. GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD **7d623fc = row 18i wiki trio LANDED** —
verified read-only at this docs pass: `git -C /tmp/RustyPig.wiki log -1`
prints `7d623fc row 18i: status + deviations + stats (107 commits / 421
files / 50,576 src lines / 557 tests ...)` and the 18i trio greps
PRESENT (`Porting-status.md:99` status row + `:109` chapter note +
`Deviations-from-Snort-3.md:2029` deviations header — the EARLIER NEXT
edition's "the ONLY owed trio is 18i, wiki HEAD 2fdaaae" line is
SUPERSEDED by this measurement: the trio LANDED as measured BETWEEN the
passes; this docs pass touched the wiki ZERO times, `git status
--porcelain` in the wiki clone = 0). **The 18j wiki trio is OWED** and
is owed at the NEXT WIKI phase, not by this docs pass
(`grep -rn 'row 18j' --include='*.md' /tmp/RustyPig.wiki` = **0 hits**
verified THIS pass; `row 18i` = 3 hits = the landed trio). The owed
trio = status row (misc/cd_icmp4_ip+cd_icmp6_ip, 507 L ground -> 770 L
Rust + 636 L replay test; THE hidden-BUILDING_SO-table headline, 17th
straight zero-gate face, the MEASURED +1 witness delta + tracked
witness face) + the row-18j deviations section (copy from KNOWN
DEVIATIONS.md :3346-:3520) + stats line ("109 commits / 431 tracked
files / 51,350 src lines / 565 tests" — LIVE values at THIS docs pass,
re-measure at the wiki pass before typing).

## 18j close-out — VERIFY MODE (plan row + deviations shipped WITH code commit 76c1c16; this pass greps-verify + re-ground rather than append)
Like 18b-18i, 18j's plan row and deviations section shipped inside the
CODE commit, so this docs pass is a verification pass. Everything below
was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18j |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:89) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what 76c1c16 shipped (`git show
  --shortstat 76c1c16`: **14 files changed, +2,530 / -0** — EXACTLY 14
  staged paths re-listed THIS pass: 7 harness files + 2 src TUs +
  mod.rs + parity test + .gitignore + plan + deviations — plan-first
  staging face; the row's own tail claim "Deviations: ... count-guarded
  0->1" VERIFIED by the devs grep below).
- **Deviations section**: `grep -c '^## codecs misc icmp ip pair (row 18j'`
  = **1** at **:3346**, running to EOF at **:3520** = **175 L**, **15
  bullets** (`sed -n '3346,$p' | wc -l` and `grep -c '^- \*\*'` THIS
  pass). **Verdict: ADEQUATE-READ-LEAVE** — the get_proto_name seam
  (the MEASURED +1 / typed +2 HALF WRONG face), the hidden BUILDING_SO
  table arms, the GROUND-DEAD cc:77-:82 second gate, the switch-arm
  oddity, the ground-stale encode() comments, the uint16 wrap, the
  obfuscate seam, the #if 0 block, row-scoped vocab, the CppUTest
  dialect census, vector discipline, seam types, the record census and
  the clippy face ALL re-grounded. **NO in-repo cite drift found at the
  18j artifacts face** (76c1c16 message cites — witness_miscip 27 L
  `c5b498ff…`, vectors 23 L/11 L md5s, mod_ctor=0/mod_dtor=0 x2 — all
  re-verified byte-true THIS pass); ONE scoping-line correction
  recorded land-rule-style (nothing rewritten): the orchestrator-
  briefing line "devs 18j = 176 L / 11 bullets" is HALF WRONG vs the
  live **175 L / 15 bullets** face measured above — the EOF-anchored
  section was never line-cited in-repo, so no artifact needs touching;
  the measurement supersedes the briefing. ALSO: `src/framework/
  codec_api.cc` does NOT exist — the codec_api.cc with the extern
  census lives at ground `src/codecs/codec_api.cc` (re-grepped THIS
  pass); the Rust ladder is `src/codecs/codec_api.rs` (path face for
  any future grep, NEVER guessframework).
- **Harness FRESH x2 THIS pass, rc 0 both runs**: `MISCIP_HARNESS_OK
  vectors=23 faceA=11 gates=0` tail verbatim BOTH, LOGS byte-ident run
  A vs B (`cmp` rc 0, receipts
  `/opt/data/cache/scratch/row18kdocs/miscip_{A,B}.log`). vectors DEC
  23 L md5 `43b259ac8b77320ff9ddaa80dde1a36e` + FACE-A 11 L md5
  `e4c47bac93a15af4ecfdc9a0bd1abe62` + witness_miscip.cc 27 L md5
  `c5b498ffa6beac768f34e25830c552a1` re-summed **byte-stable after the
  fresh x2 rebuilds** (drift-then-refuse guards armed, zero drift).
  ALL 7 tracked faces re-counted (`git ls-files tools/miscip_harness` =
  **7**: build.sh 606 L `c7e55448…`, PLAN.md 114 L, probe.cc 43 L,
  probe_dec.cc 92 L, vectors 23 L, faceA 11 L, witness_miscip.cc 27 L).
  Runner echoes re-read in the fresh logs: copy tree find-count **mid-
  build 106 / post-strip 105** (the daq graft NEVER stays), row-TU nm
  census **icmp4_ip=18 icmp6_ip=10 union=18 (tunnel_bypass 0/0)**,
  frozen census echo `9/25 holders of 4826fc22, 17 distinct`,
  O0==O2 BYTE-IDENT both faces. `git ls-files tools/miscip_harness |
  wc -l` = 7 = the stageables face; .gitignore miscip block **:468-
  :493** re-verified by `git check-ignore` THIS pass (`copy/` :472,
  `o2/` :473).
- **Git-face VERIFY (the positive lesson, see PROCESS LESSONS)**: 76c1c1
  reflog entry reads plain **`commit:`** — NO amend, single push,
  origin/master == HEAD (`rev-list --count` both = **109**), i.e. the
  18i rule HELD FIRST TRY at 18j. The 18i orphan **69c8b6f NOT an
  ancestor of origin/master RE-PROVED THIS pass cheaply
  (`merge-base --is-ancestor 69c8b6f origin/master` rc **1**; receipts
  face unchanged).
- **ZERO-GATE ARTIFACTS — face ENFORCED, census UNDISTURBED**: TWO-LINEAGE
  census MEASURED at this docs pass OUTSIDE the harness too:
  `ls tools/*/gate.txt | wc -l` = **25**, md5 holders of `4826fc22…`
  = **9**, distinct md5s = **17**, `git ls-files 'tools/*/gate.txt'` =
  **1** (gre's — still the only tracked gate), gre anchor re-md5'd
  `6751d1a8…` byte-exact. miscip added ZERO gate files: 18j = the
  **17th straight honest zero-gate face**. **Frozen lineage verified the
  sanctioned way** — direct md5 re-sums, frozen donors NOT chased to
  rc 0: daq3 vectors `fd1855e1` + faceA `2fb9dc45`, small4 `462f0ff6`
  / `4755d48c`, tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`,
  eth `1bd98dbb`, csum `e4baf781`, fmod vectors `f0fdbab`, vocab
  vectors `5da70e82`, witness census `9fad7e9d`/`be9bdd0b`/`f4afd35f`/
  `ea1f79f3` + daq3-regen witness_conf `4dd91018` — ALL byte-exact
  THIS pass (18/18 files zero drift).
- **Gate chain frozen side — MEASURED not asserted**: gre rebuilt
  FRESH x2 THIS pass rc 0 BOTH (LOGS byte-ident receipts
  `row18kdocs/gre_{A,B}.log`, gate `6751d1a8` + vectors `41bd7d1b` /
  `783649440d` re-md5'd); fmod FRESH rc 0 (gate `4826fc22` echo, tail
  vectors/gate md5 lines + `FMOD_HARNESS_OK vectors=61`, vectors
  `f0fdbab` stable); vocab FRESH rc 0 (`VOCAB_HARNESS_OK vectors=29`).
  Receipts `/opt/data/cache/scratch/row18kdocs/{miscip_A,miscip_B,gre_A,gre_B,fmod,vocab}.log`.
- **Rust-side anchors re-grounded THIS pass**: pair TUs **529 + 241 =
  770 L FLAT** (wc THIS pass; `src/codecs/mod.rs` pub-mod pair at
  :64/:66 + doc rows :44-:45, `grep -c 'pub mod'` = 27); the ladder
  post-18j face (`src/codecs/codec_api.rs`): `STATIC_CODEC_EXTERN_NAMES:
  [&str; 34]` still at **:97** (the miscip build.sh :81 sed-pin proves
  it EVERY build) — cd_icmp4_ip **:113** / cd_icmp6_ip **:115**
  (LOADED names post-18j), cd_icmp4 :112 / cd_icmp6 :114 / cd_udp :128
  line cites from the 18h/18i editions STILL TRUE (zero ladder drift —
  the names were resident before the landing and the array was NEVER
  re-sorted); the misc-trio names ALREADY resident: cd_llc **:117** /
  cd_user **:129** / cd_vxlan **:131** (the 18k hand-off face, NEVER
  re-touched). framework/codec.rs + parse_conf.rs + codec_api.rs +
  codec_module.rs BYTE-UNTOUCHED at 76c1c16 (the commit's src/ diff
  face = 2 new TUs + mod.rs ONLY, re-checked via the 14-path list);
  the 39-extern cc census re-counted = **39** (ground
  `src/codecs/codec_api.cc`).
  `#[no_mangle]` honesty face: `grep -rn '#\[no_mangle\]' src/` = 4
  hits but ALL four are DOC-comment text inside the two new TUs —
  **ZERO attribute sites** (the 18j "ZERO #[no_mangle]" claim stands at
  the attribute face, the grep face is doc-text, record it precisely).
- **Test math**: 565 = 557 + 8; plain `cargo test` 68 result lines,
  summed programmatically 565 passed / 0 failed, FAILED/panicked grep 0,
  at THIS pass (receipt `row18kdocs/cargo_test_18kdocs.log`); 41 parity
  files (40 + miscip).
- **commit census + gitignore**: 109 at HEAD 76c1c16 (origin 109,
  clean); `git status --porcelain` **EMPTY** (wc 0) after ALL docs-pass
  rebuilds — artifacts fully absorbed.

## PROCESS LESSONS — the 18i amend-after-push incident (rule section) + the 18j HELD face (positive lesson)

THIS IS A RULE SECTION, NOT A FOOTNOTE. The 18i row committed a
git-face violation of the lineage's own land rule, then corrected it
in-ref; 18j executed the rule CLEAN (single `commit:` reflog entry,
single push, no force); every future agent must read this before
touching a pushed commit.

**What happened at 18i (transcript timestamps, `git reflog` +
receipt-file mtimes):**
- `2026-11-21 02:10:27` — commit **69c8b6f** = row 18i lands.
- `2026-11-21 02:10:33` — `push origin master` succeeds:
  `origin/master@{1} = 69c8b6f ("update by push")`. THE PUSH CLOSED THE
  AMEND WINDOW at this moment.
- `2026-11-21 02:10:35` — `build_E.log` rc 1: the FIRST post-commit
  ritual run; the pre-commit dirty-4 whitelist guard strands the EMPTY
  post-commit face (the session-start ritual runs with the row LANDED).
- `2026-11-21 02:15:37` — `build_F.log` + `build_G.log` rc 1 x2: the
  harness carried a NO-PRECEDENT own-repo HEAD self-pin (`build.sh:157
  == 8d2712a`, creation-time seed) that strands the ritual after EVERY
  landing by design.
- `2026-11-21 02:18:09 / 02:19:50` — guard re-ruled in the working tree
  (`build.sh.bak2` / `build.sh.with_tail` scratch backups): dirty face
  becomes a row-face regex (accepts EMPTY + this row's 15 paths, fires
  on any other row's file), self-pin DROPPED with in-situ comment.
- `2026-11-21 02:20:54` — **e6f5616 committed via `git commit --amend`
  of the ALREADY-PUSHED 69c8b6f** (reflog HEAD@{0} literally reads
  `commit (amend)`; subject byte-identical — `diff` of both messages =
  IDENTICAL verified at the 18i docs pass; content delta `git diff
  69c8b6f..e6f5616` = 3 files +33/-19: guard text + honesty records
  ONLY; vectors/ground/landed Rust NEVER touched).
- `2026-11-21 02:20:56` — `push --force-with-lease` REWROTE
  origin/master: `origin/master@{0} = e6f5616` displaced
  `origin/master@{1} = 69c8b6f`. 69c8b6f is NOT an ancestor of the
  current origin/master — **RE-PROVED AGAIN THIS (18j) pass**,
  `merge-base --is-ancestor` rc 1.

**Why it was wrong (even though the payload was clean):** `--force-with-lease`
makes a rewrite SAFE against clobbering others — it does NOT make it
PERMITTED. The ONE-COMMIT-PER-ROW goal NEVER outranks push immutability.
The lineage's own land rule — codified at 18f (message twice says "no
force-push") and 18h ("rows/sections/messages NEVER rewritten") —
applies to COMMIT OBJECTS, not just file contents, and 18i violated it
against its own text. Note the legal precedent for contrast: the 18g
docs commit was AMENDED (97104e4 -> a7c976a, reflog) but 97104e4 was
NEVER pushed (absent from the origin/master reflog) — a PRE-push amend
is inside the one-commit discipline; a POST-push amend is history
rewriting. The amend window closes the instant the push helper returns
success.

**The 18j HELD face (POSITIVE lesson — the rule works):** 76c1c16
landed 04:54Z as a SINGLE commit (reflog `commit:`, NEVER
`commit (amend)`), pushed ONCE, origin == HEAD 109/109 measured THIS
pass; the guard-self-pin and dirty-N whitelist anti-patterns were
NEVER reintroduced (miscip build.sh uses the landed FACE-AGNOSTIC
row-face regex + ground-identity re-pin, and its second-landing census
`:18`/`:102-:105` stayed green POST-landing — the 18i lesson made the
18j ritual survive its own landing by design). The rule forward is now
tested in both directions: violated once (18i, logged, never hidden)
and held once (18j, measured above).

**The rule forward (binding on every future row):**
1. Post-push fixes ship as a FOLLOW-UP COMMIT (a second commit on the
   row — harness-guard fixups, docs corrections — with its own honest
   message and receipts kept), or ride the NEXT docs commit. NEVER a
   post-push amend, NEVER a force of any flavor (`--force-with-lease`
   included). ONE-COMMIT is a goal pursued BEFORE the push; push
   immutability is the hard constraint AFTER it.
2. Harness git-state guards must be FACE-AGNOSTIC: daq3 build.sh
   :660-688 (row-face regex) — cloned at 18j — is the landed template;
   NEVER a fixed dirty-N whitelist, NEVER a harness that dies at its
   own row's post-commit face.
3. NEVER pin the working repo's own HEAD in a harness (a self-pin is a
   creation-time face that dies at every landing). Pin the IMMUTABLE
   ground only (miscip/daq3 ground-identity re-pins; NEVER re-type the
   sha-cite line numbers — sed the landed file).
4. The rc1 faces stay as receipts and in deviations — the honesty
   record exists; only the git MECHANISM was wrong at 18i.

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript. vectors.txt is a tracked
   INPUT the build re-verifies but NEVER fabricates (18d lesson;
   FIRST-RUN-SEED then drift-then-refuse face, miscip build.sh wc 23/11
   pins + the cmp arms; vectors md5 byte-stable across the fresh x2
   docs-pass rebuilds THIS pass).
2. **Catch gate** whenever upstream ships an embedded
   `#ifdef UNIT_TEST` block or a `test/` suite: compile it verbatim
   (`catch/snort_catch.h` -> plain-catch shim; the FRESHEST working
   shape stays at GRE: `tools/gre_harness/build.sh` :132 catch.hpp cp +
   :139 catch_main.cc heredoc + :143 CATCH_CONFIG_MAIN pin;
   TestCaseInstaller REJECTED at 18g, deviation :2928-:2939). Run it;
   record cases/assertions in `gate.txt`; an embedded-Catch codec row's
   gate.txt is TRACKED with pinned md5 + wc + the runner's own tail
   wording (the gre pattern). NEVER gate on grep-estimated assertion
   counts (17p). Duplicate-symbol rule when gate and probe link the
   same TU (E9 face at gre). Zero-suite rows run the **zero-gate face**
   (`test ! -e gate.txt` + NO Catch symbols asserted IN the build +
   the two-lineage census loop (9/25/17-style) + the stageables -eq N
   face; a row whose witness IS the evidence face TRACKS the witness
   file — daq3 AND miscip = 7 tracked faces each, census re-asserted
   every build). The 17y INVERSION lesson, the 18a PER-LINK corollary,
   the 18b PROBE-ONLY corollary, the 18d INVERTED-DUP face, the 18e
   FACE-RULE, the 18g TWO-LINEAGE codification, the 18h peg-vs-hook
   grep correction and the 18i git-face rules (amend window /
   face-agnostic guards / no own-HEAD pins) all stand. A fake Catch
   gate over a suite-zero row = the 17p anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced and every one gets a section
   in `KNOWN DEVIATIONS.md`. 18i/18j reinforcements: a missing external
   header is met by a MINIMAL measured graft built ONLY off the
   use-site symbol census (`copy/daq.h` 33 L in daq3 ONLY, NEVER re-
   applied — the GRAFT-NEVER-REAPPLY tripwire fires at every later
   build), never trim ground C, never pure-defer an include that rides
   ground TUs; dead-in-C gates/comments transcribe LITERAL with pins
   (18j: the cc:77-:82 re-check, the cc:108 ICMPV4-in-v6 switch, the
   encode() comments); a witness body is never worth unbounded closure
   (18j REAL-body rc1 -> the cited-minimal fixed-string witness,
   cite-never-vectorize).
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-index assert, ORDERED, never set-membership),
   donor pattern: `tests/miscip_parity_test.rs` (636 L, 8 tests — the
   hidden-table tripwire unit + CppUTest dialect census unit + the
   cite-line-with-zero-decode face), `tests/daq3_parity_test.rs`
   (1,269 L, 8 tests — dual face + drift tripwire + the
   EXISTENCE-but-UNLOADED pin now turned loaded, text NEVER rewritten),
   `tests/small4_parity_test.rs` (802 L, 8 tests — name-drift-IN-
   transcript), `tests/gre_parity_test.rs` (723 L, 11 tests — the
   GATE-row pattern), plus tun/eth/vocab/csum.
5. **Gates at EVERY commit**: `cargo test` all green (>= 565; never
   trust a summed total from a run containing FAILED; cite one face per
   pass), clippy --all-targets ZERO warnings (force relint by touching
   all .rs), `vectors.txt` md5 stable across >= 2 clean rebuilds
   (miscip FRESH x2 logs byte-ident THIS pass), harness `.gitignore`
   block added (mirror siblings) and verified with `git check-ignore`
   BEFORE staging (the miscip block is .gitignore:468-:493, landed
   inside code commit 76c1c16). Then commit + push, insert the plan row
   (grep-guard: count must be 0 before insert), append deviations (one
   grep-guarded append) — the 18b-18j variant: BOTH ship inside the
   code commit, then the docs pass VERIFY-greps them (count == 1 each)
   and still re-measures every load-bearing claim. Refresh NEXT.md
   (FRESH rewrite), commit+push docs. ONE code commit + ONE docs
   commit, each pushed ONCE, NEVER amended, NEVER force-pushed (the
   18j face proves the cadence works clean). Wiki: status row +
   deviations section + stats line at the WIKI phase — queue status
   measured at THIS pass: the 18i trio is LANDED (7d623fc), the ONLY
   owed trio is 18j.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote. A push is ONE-WAY (see PROCESS LESSONS): after it returns rc 0, fixes ride follow-up commits, never `--amend`/`--force-with-lease`.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. 17s/18b-18j do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH; nm pin fmod build.sh:961). Row-TU lua-seam assert carried every build since 18d.
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum/vocab/eth/ext/tun/gre build + the 18j misc/test dialect census add_cpputest x3: `ip/test/` and `misc/test/` are CppUTest dialect ONLY). Upstream CppUTest suites can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp `74ef54e8` + shim) runs natively — the cd_gre gate ran REAL at 18g. **ip/checksum.h DONOR-RESIDENT** (`b43628f3` ground face): pgm rode it at 18h, the 18i trio rode it too. `log/text_log.h` `3e827113` resident via the tun lineage.
- **`#include <daq.h>` IS A LANDED-ONCE GRAFT** (face CHANGED at 18i, PROTECTED since): ground tree + host have NO daq.h (`find /opt/data/snort3-src -name 'daq.h'` = 0; NEVER confuse: `daqs/daq_user.h` 54 L, `src/pub_sub/daq_message_event.h`, `src/packet_io/sfdaq*.h` are ALL different faces) — `tools/daq3_harness/copy/daq.h` 33 L md5 `73fdbc3983ca45246b554c46efdf1ad1` is committed, and the miscip build.sh GRAFT-NEVER-REAPPLY tripwire (`find $SRC -name daq.h` = 0 + the tools-side second-landing census) stayed GREEN post-18j: the 18j pair carries ZERO daq includes (grep 0/0 measured again in the fresh build echoes). **Riders banked**: `ip/cd_{ipv4,ipv6,tcp}.cc` AND `link/cd_vlan.cc` all `#include <daq.h>` — those rows ride the daq3 graft for free (the copy-tree face at their rows is a PLAN-0 measure — the current landed HEAD tree is the miscip copy, 105 post-strip, daq.h STRIPPED: a rider row RE-APPLIES the tracked graft file, NEVER re-authors it). **NEVER confuse the TWO daq graft faces**: `daq.h` (33 L, daq3, daq_msg_get_data/_meta witnesses) vs `daq_common.h` (16 L md5 `f683749c…`, fmod home, RESIDENT in the miscip copy tree — re-md5'd byte-ident THIS pass; the 18k user.cc row RIDES daq_common.h, NOT daq.h). The daq fns (`daq_msg_get_data`/`daq_msg_get_meta`, SYNTHETIC bodies) stay the lineage's graft-borne fn witnesses; raw.daq_msg PROVENANCE stays OPEN (17d ruling; row 20 cites the real SDK). vocab `daq_dlt.h` 5 L graft unchanged.
- **Hidden BUILDING_SO table face is NOT pair-specific**: the 18j census generalizes to the misc/ family — `grep -c BUILDING_SO` over the 18k trio = **1 / 1 / 1** (measured THIS pass, cd_llc :190-:194 / cd_vxlan :124-:128 / cd_user :158-:162); every misc/ sed census MUST pin the ifdef arms, the string `cd_<name>[]` NEVER exists in a .so face (`snort_plugins` 1/1 each).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 + 18d-18j replay mirrored Rust-side: R6 var-first census `bool-b=-eq` at 14 miscip probe_dec arms, `printf.*->decode` 0).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY. Since 18a `file_trace` has its REAL def on BOTH sides.
- Frozen-donor build.sh rc-1 face (the 18g drift codified): tun/eth/ext die at their point-in-time `-eq 24` gate.txt ls-asserts (tun :334, eth :598, ext :320) since gre added the 25th gate — BY DESIGN, NEVER edit frozen scripts; verify their frozen face by DIRECT vectors md5 re-sums (re-done THIS pass: tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`, eth `1bd98dbb` — all byte-exact).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/miscip_harness/` — **THE donor for row 18k+ (lineage head, ZERO-gate + tracked witness + hidden-table census shape)**: exactly **7** tracked files (build.sh 606 L `c7e55448…`, PLAN.md 114 L, probe.cc 43 L, probe_dec.cc 92 L, vectors.txt 23 L `43b259ac…`, vectors_faceA.txt 11 L `e4c47bac…`, witness_miscip.cc 27 L `c5b498ff…`); NO gate.txt, NO catch_main. Self-checks re-run THIS pass at BOTH fresh rebuilds (rc 0 logs byte-ident): ground md5 x2 + wc x2 + the **-eq 507** sum pin :40; hidden-table sed pins (BUILDING_SO :47 section; the pair spans under test :336-:343 / :154-:161); 39-extern cc census :77; misc/test dialect census :87 (add_cpputest x3, TEST_CASE 0 x3, STOP-flag probe NEGATIVE); ladder `[&str; 34]` :97 sed-pin :81 + the daq3 contains-both arms :84-:85; witness-body honesty (packet_manager.cc :1004 def cite + the :179/:297 call-site pins :104-:109, the icmp6 ZERO-ref -eq 0 pin); donor find-count **-eq 103** live-head-face :116 -> mid **-eq 106** :141 (asserted MEASURED, NEVER pre-typed); per-include residency census x7 + tcp.h find-0 :117-:120; E4 flipped walls EVERY build (tcp.h -> ONLY cd_icmp4_ip DIES; daq.h -> trio x3 DIE + pair SURVIVE = the DAQ-free split face; udp.h/icmp4.h cross-rider arms) + restored rc0 x5; nm per-TU U echo `18/10 union 18 tunnel_bypass 0/0`; staged L1 undefined-DISTINCT-EXACTLY-1 -> +witness GREEN; stageables -eq 7 untracked-then-tracked face; vectors wc pins 23/11 + O0==O2 cmp arms; frozen census loop `9/25/17 + tracked-1`; row-face dirty guard regex (the 18i template clone). **Copy tree HEAD face: 105 post-strip** (103 daq3 donor + tcp.h + 2 pair TUs = 106 mid, daq.h stripped end-of-build — trio TUs + pair TUs STAY additive).
- `tools/daq3_harness/` — the 18i ancestor (NOW frozen-lineage face; direct md5 verification sanctioned, done THIS pass `fd1855e1`/`2fb9dc45` byte-exact): exactly 7 tracked files (build.sh 695 L `3d6a6d9b`, PLAN.md 134 L `a9d3cdbc`, probe 35 L `7f4f1c84`, probe_dec 236 L `3af12201`, vectors 93 L, faceA 13 L, witness_daq.cc 54 L `e0166b02`); THE daq.h graft home (copy/daq.h 33 L `73fdbc39`, never re-authored); the row-face dirty-guard template :660-:688.
- `tools/small4_harness/` — the 18h donor (frozen-lineage face): 6 tracked files (build.sh 453 L `2e698080`, PLAN.md 73 L, probe 37 L, probe_dec 163 L, vectors 46 L `462f0ff6`, faceA 17 L `4755d48c`); copy tree 96 face; ZERO-gate face + first FIRST-RUN-SEED drift-refuse.
- `tools/gre_harness/` — **THE gate-shape donor (18g; kept for ANY row with real Catch/Catch-suite material)**: exactly 8 tracked files, gate.txt 3 L md5 `6751d1a8` TRACKED (tail `All tests passed (1 assertion in 1 test case)`, pins :378-:382), vectors `41bd7d1b` 26 L + faceA `783649440d` 5 L, build.sh 412 L, anchors :43-:49, catch shape :132/:139/:143, E9 dup flipped-assert, rfind+cut-to-EOF excision, census loop :401-:404. Rebuilt FRESH x2 THIS pass, rc 0, logs byte-ident. ALSO the tunnel-bypass witness carry face: build.sh :19 (the ONE `tunnel_bypass_enabled` witness rides from tun), :170 `-ge 1` grep on `tun_harness/witness_18f.cc`, :298 exactly-ONE-U-line census — the 18k vxlan row clones THAT.
- `tools/tun_harness/` — 18f ancestor (7 tracked files; `-eq 24` line dies by design): vectors `2a792479` + `81602890`, witness_18f.cc `ea1f79f3` (**the `SnortConfig::tunnel_bypass_enabled` witness def at witness_18f.cc:16** — the banked bypass-hook witness, GRE arm rides the SAME). Direct-md5 face ONLY.
- `tools/ext_harness/` — 18e ancestor (7 tracked files): DUAL faces `da218429` + `0fa79b53` zero drift. `-eq 24` face dead by design.
- `tools/eth_harness/` — 18d ancestor (5 tracked files): stubs_18d.cc `f4afd35f` RETIRED marker; vectors `1bd98dbb`.
- `tools/vocab_harness/` — the 18c ancestor (rebuilt FRESH THIS pass rc 0 `VOCAB_HARNESS_OK vectors=29`): witness_stubs.cc `9fad7e9d` — the 4 stub tables :11-:14 (cd_ipv4 :11 / cd_ipv6 :12 / cd_tcp :13 + cd_hopopts RETIRED face) frozen by vectors:25-:28 — **the heavyweight trio's retirement landmine lives at :11-:13**; vectors `5da70e82` stable; `daq_dlt.h` graft home.
- `tools/fmod_harness/` — the 18a donor & **FROZEN gate-lineage source** (rebuilt FRESH THIS pass rc 0 `FMOD_HARNESS_OK vectors=61`, gate `4826fc22`, vectors `f0fdbab`): cp braces + objs loop carry the FULL file_api closure; libluajit.a BY PATH, nm pin :961; catch-recipe carry :249/:270; **daq_common.h 16 L graft home** (that graft is RESIDENT in the miscip copy tree, byte-ident `f683749c…` re-md5'd THIS pass).
- `tools/csum_harness/` — row 18b, the probe-only origin: ground-header md5 pin :37, E4 wall receipt :67-:70, nm ZERO-text-symbols :79-:80, O0==O2 :116, vectors 16L md5 `e4baf781` re-md5'd THIS pass.
- `tools/flog_harness/` (17z): 50L `b260ec6a`. `tools/fsvc_harness/` (17y): 64L `54864705`. `tools/fpolicy_harness/` (17x): 27L `b989a8d5`. `tools/finspect_harness/` (17w): 103L `3cbd009e`. `tools/fcapi_harness/` (17v): 21L `a953a501`. `tools/fconf_harness/` (17u): 20L `65968e1c`. `tools/fcshare_harness/` (17t): 25L `03d43c14`. `tools/fcap_harness/` (17s): 27L `0208a691`; gate `4826fc22` — frozen chain START.
- `tools/fctx_harness/` — vectors 610L `839b5566`; gate `42349372`. `tools/fflows_harness/` 146L `bd8c00af` (DO NOT touch), gate `e14626fc`. `tools/fcache_harness/` 278L `b69db310` (DO NOT touch), gate `6b3c041e`. `tools/filib_harness/` 273L `77ffd8e4` (DO NOT touch). `tools/textlog_harness/` — time() interposition precedent. `tools/rules_harness/` — hosts `copy/catch/catch.hpp` `74ef54e8`. **`tools/codec_harness/` is row 17d's harness** (stubs.cc md5 `be9bdd0b…` re-confirmed THIS pass is the FROZEN donor the E6-YES arms re-collide against) — the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.

## Next milestone — row 18k: the misc leftovers trio (llc + vxlan + user), FRESH-measured at the 18j docs pass — OR the heavyweight stub-retirement trio (PLAN-0 call, alternatives below)

### The trio face, measured THIS pass (ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY; residency vs the MISCP copy tree = the landed 105-tree head)
- **Size + gate**: `misc/cd_llc.cc` **198 L** + `misc/cd_vxlan.cc` **133 L**
  + `misc/cd_user.cc` **167 L** = **498 L** (wc THIS pass). Gate material
  combined grep `TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST` = **0/0/0** —
  honest probe-only row; the **18th-zero-gate-chance** row, miscip is
  the clone donor. `misc/test/` = CppUTest dialect ONLY (add_cpputest
  x3 — geneve/gtp/teredo test files; llc/vxlan/user ship NO suite files,
  ls THIS pass) => ZERO new dialect material, the 10 already-translated
  names (18f face, tests/tun_parity_test.rs) carry NOTHING new at this
  row.
- **Hidden BUILDING_SO tables x3 (the 18j census GENERALIZES)**: ALL
  THREE hide their tables under the ifdef — cd_llc.cc :190 `#ifdef` /
  :191 snort_plugins / :192 `#else` / :193 `cd_llc[]` / :194 `#endif` /
  record `&llc_api.base` :196; cd_vxlan.cc :124/:125/:126/:127/:128 +
  `&vxlan_api.base` :130; cd_user.cc :158/:159/:160/:161/:162 +
  `&user_api.base` :164; `grep -c BUILDING_SO` = 1/1/1 + snort_plugins
  1/1/1 measured. The sed census pins file + ifdef EVERY build (the
  18j arms :336/:154 clone).
- **TRUE-NAME clean x3**: llc `LLC_NAME "llc"` :30 / `llc_api` :168 /
  table `cd_llc[]` :193 (file base == table base == NAME); vxlan
  `CD_VXLAN_NAME "vxlan"` :31 / `vxlan_api` :102 / `cd_vxlan[]` :127;
  user `CD_NAME "user"` :33 / `user_api` :136 / `cd_user[]` :161.
  File-vs-table greps armed with NOTHING to catch (the drift-family
  posture, cd_ah/ipv6_api precedents).
- **Record census (the mixed face — do NOT carry the pair's 0/0)**: llc
  mod_ctor/mod_dtor REAL :156/:159 (api slots :179/:180 — a LlcModule
  RULES-owning module, contrast pair nullptr); user nullptr-pair
  :147/:148 (0/0, pair-shape); vxlan nullptr-pair base block
  :113/:114 (the sed dump of :102-:119; pinit..tterm at :116-:119) —
  the 18j vectors faceA
  asymmetry pin EXTENDS per-TU at 18k, pin all three separately.
- **Includes/residency (measured vs the miscip copy tree)**: cd_llc
  :21-:26 = config.h + codecs/codec_module.h + framework/codec.h +
  log/text_log.h — **ALL resident (find 1 x4) = ZERO fresh cp** for the
  llc TU. cd_vxlan :21-:27 = config.h + framework/codec.h + text_log.h
  + main/snort_config.h + **packet_io/active.h :27 — active.h find 1 =
  RESIDENT in the miscip copy tree** (the 18i-era "active.h resident"
  claim CONFIRMED at the landed head tree) + snort_config.h find 1 ->
  **ZERO fresh cp** for vxlan too. cd_user :21-:29 = config.h +
  **`<daq_common.h>` :24 = RESIDENT** (copy/daq_common.h 16 L
  `f683749c…` byte-ident to the fmod graft, re-md5'd THIS pass — the
  fmod graft RIDES, and it is the daq_common face, NEVER the reaped
  daq.h) + framework/codec.h RESIDENT + **daqs/daq_user.h :26,
  packet_io/sfdaq.h :28, packet_io/sfdaq_instance.h :29 = 0-hits =
  THREE fresh-cp candidates (ground wc 54 + 72 + 105 = 231 L, wc
  THIS pass)**; their own includes ride resident
  main/snort_types.h + protocols/protocol_ids.h (find 1 x2 measured).
  **user is the row's ONLY closure risk: the FRESH-CP count is a
  PLAN-0 MEASURE (add ONLY what measures fresh at build time), the
  user closure face is the ONLY non-zero one in the trio.**
- **tunnel_bypass check — THE vxlan headline (the hook seam RETURNS, with cites)**:
  cd_vxlan.cc :73-:74 `if ( codec.conf->tunnel_bypass_enabled
  (TUNNEL_VXLAN) ) codec.tunnel_bypass = true;` (the ground CONF-hook
  face, NOT the 18i trio's peg face — peg-vs-hook, 18h lesson) +
  :79 `codec.codec_flags |= CODEC_NON_IP_TUNNEL`. The mask const:
  `TUNNEL_VXLAN = 0x100` at **snort_config.h :127** (enum block
  :119-:128 sed-pinned THIS pass). HOOK SEAM STATUS: the C-link face
  `SnortConfig::tunnel_bypass_enabled` defs at snort_config.cc :1020 +
  decl snort_config.h :777 — snort_config.cc was NEVER compiled in any
  donor, but the LINEAGE BANKED THE WITNESS: **witness_18f.cc :16
  carries the def** (tun 18f), gre build.sh :19/:170/:298 rides +
  censuses exactly-ONE-U-line — vxlan CLONES that carry face (expected
  delta ZERO new tunnel-axis fns, MEASURE at PLAN-0). Rust side the
  seam is FULLY LANDED: `bypass: &mut dyn FnMut(u16) -> bool` param
  (cd_geneve.rs :300), `if bypass(TUNNEL_GENEVE) { codec.tunnel_bypass
  = true; }` :361-:362, cd_gtp.rs :327 / cd_gre.rs :576 same shape,
  field at framework/codec.rs :236/:258. **tunnel_decap face ANSWERED
  too: it is NOT a codec-row face at all** — ground grep = exactly **4
  hits, ALL packet_manager.cc** :232/:395/:397/:401 (`tunnel_decap_
  pending`, the PacketManager walk) — the vxlan decode NEVER touches
  it; row-20/PacketManager owns it, cite-never-port posture.
- **Vocab homes**: `PROTO_BIT__VXLAN 0x040000` decode_data.h **:105**
  sed-pinned (OR-group :122 cites it with GTP/TEREDO/GENEVE siblings) =
  **ZERO landed Rust face** (grep 0 THIS pass) -> row-scoped const (the
  18j per-TU precedent). `CODEC_NON_IP_TUNNEL 0x0200`
  **framework/codec.h :101 = ALREADY LANDED** at framework/codec.rs
  :51 (the gre/geneve/gtp/teredo riders' face) -> IMPORT for vxlan.
  Protocol ids: `ProtocolId::VXLAN = 0x0108` protocol_ids.h :135 =
  ALREADY landed ROW-SCOPED in cd_udp.rs :146-:147 (the cc:458 arm);
  `ETHERNET_802_3 0x0105` :132 ALREADY landed (cd_eth.rs :123-:126
  const + protocol_id face) -> the duplicate-vs-import ruling continues
  (framework `protocol_id::` members import; per-file rows duplicate;
  PLAN-0 per the cd_icmp6.rs:183 precedent cite, NEVER air). llc:
  `ETHERNET_LLC = 0x0107` protocol_ids.h :134 is ALREADY a framework
  member `protocol_id::ETHERNET_LLC` (codec.rs :167-:169) AND used by
  cd_eth.rs :150 -> llc get_protocol_ids (:91) imports, NO new const.
- **Rules/sids**: llc is the trio's ONLY rules face — `static const
  RuleMap llc_rules[]` :35-:40 = EXACTLY **2 sids** `DECODE_BAD_LLC_
  HEADER 131` / `DECODE_BAD_LLC_OTHER 132` (codec_module.h :80-:81,
  sed-pinned) — **BOTH ALREADY landed in Rust** `src/codecs/
  codec_module.rs :97-:98` (grep THIS pass) = **ZERO new DECODE_*
  constants**, llc RuleMap rows = 2 (first misc rules row since 18f-
  family faces; replay pins the 2-event name face). vxlan + user:
  RuleMap grep = **0/0** — ZERO sids (contrast llc 2; the trio face is
  2/0/0).
- **user.cc — THE DAQ seam row of row 18 (the face that was queued)**:
  decode :99-:121 = `DIOCTL_QueryUsrPCI qup = { raw.daq_msg, nullptr }`
  :101 + `SFDAQ::get_local_instance()->ioctl(DIOCTL_QUERY_USR_PCI,
  ...)` :103 != DAQ_SUCCESS -> false, pci null -> false, `pci->ip_proto`
  -> set_ip (:82 def :51; the 3 `DAQ_USR_FLAG_TO_SERVER/START_FLOW/END_FLOW`
  :84/:87/:90 arms + the pci->ip_proto TCP/UDP proto_bits face :62-:66)
  + `set_pkt_type(PktType::USER)` :114 ELSE set_key
  (:68 def — the hard-coded FIXIT-L 192.168.1.1/.2.2 + sp/dp
  12345/54321 face) +
  `set_pkt_type(PktType::FILE)` :119; get_data_link_type :46-:49 =
  `DLT_USER 230` (daqs/daq_user.h :29).  **Symbol census (measured —
  EXACTLY 8 symbol-hit lines + 4 include lines, `grep -c` THIS pass)**:
  DAQ_UsrHdr_t / 3 x
  DAQ_USR_FLAG / DIOCTL_QUERY_USR_PCI / DIOCTL_QueryUsrPCI / SFDAQ /
  DAQ_SUCCESS — daqs/daq_user.h:32-:34/:36+:44/:46/:47-:51 provide
  ALL EXCEPT `DAQ_SUCCESS` (SDK face, grep 0 in daqs/daq_user.h AND in
  the landed graft — **the graft-vs-witness call is the row's PLAN-0
  headline**, built ONLY off this census, the daq.h 33 L precedent:
  extend daq_common.h vs fresh daqs/daq_user.h cp vs witness-stub the
  symbol, NEVER pre-decided). **THE LINK SEAM (measure, NEVER type the
  delta)**: `SFDAQ::get_local_instance()` + the virtual `ioctl` ride
  packet_io/sfdaq.cc **420 L** + sfdaq_instance.cc **436 L** (wc THIS
  pass) = 856 L TUs NEVER compiled by ANY donor (`find tools
  -iname 'sfdaq*'` = **0** measured) = the get_proto_name situation
  AGAIN but DEEPER (a class method + vtable face, not one free fn):
  expected witness = SYNTHETIC SFDAQ class stub (the 18j cited-minimal
  route PRECEDES and fits: probe pins the false/true arms' faces, the
  REAL SDK ioctl body NEVER ports); real-cc-compile of sfdaq*.cc =
  REJECT (its own deps + DAQ SDK absence; row 20 owns packet_io).
  `raw.daq_msg` itself: framework/codec.h :38 struct _daq_msg fwd +
  RawData.daq_msg HALF-RESIDENT (17d plumbing, rides the miscip copy);
  **Rust RawData NEVER carries daq_msg (framework/codec.rs :9)** -> the
  user row RE-OLAYS the daq_msg provenance seam (the banked
  daq_msg_get_data/meta witnesses are 18i's face; here the struct-init
  uses the POINTER directly — the Rust seam form is a PLAN-0 measure,
  row-20 cites the real SDK face; the cd_icmp6.rs :47-:53 graft-seam
  precedent cites). `set_pkt_type` = document-only precedent (cd_udp
  .rs :884/:1204 "set_pkt_type no-home, module doc"); PktType::USER/-
  FILE has NO landed Rust face (grep 0 measured) — cite, NEVER invent.
- **Completeness hand-off (resident, NEVER re-touch)**: ground externs
  `cd_llc` src/codecs/codec_api.cc :59 + load :104; `cd_user` :71 +
  load :116; `cd_vxlan` :73 + load :118 (all re-grepped THIS pass);
  Rust ladder names RESIDENT in `src/codecs/codec_api.rs`
  STATIC_CODEC_EXTERN_NAMES `[&str; 34]` (:97) at cd_llc **:117** / cd_user
  **:129** / cd_vxlan **:131** (re-grepped THIS pass) — the 18k row
  TURNS those three names into loaded tables, the ladder face NEVER
  changes (the pair :113/:115 face at 18j is the template: names were
  already resident; NO test pin today names the TRIO unloaded (the
  daq3-pair-pin family covers the pair ONLY) — completeness = the trio
  test's own hidden-table tripwires + the 34-census pin).
- **Landmine posture ZERO**: `cd_llc|cd_vxlan|cd_user` grep = **0** in
  vocab witness_stubs.cc + codec stubs.cc + daq3 witness_daq.cc +
  miscip witness_miscip.cc (grep rc 1 measured THIS pass) — NO stub
  tables to retire (the trio landmine at witness_stubs.cc :11-:13
  stays heavyweight-only).

### 18k alternatives — honest comparison (measured THIS pass)
|| option | size | fresh-cp / risk face | verdict |
|---|---|---|---|
| **(a) 18k = misc leftovers trio (closes the misc/ tail)** | **498 L** (198+133+167 wc cites THIS pass) | llc + vxlan **ZERO fresh cp** (residency measured vs the 105-tree head, active.h + snort_config.h RESIDENT); user 231 L fresh-HDR candidates + the SFDAQ link-stub seam (the row's ONE hard face — the 18j witness precedent fits); hidden-BUILDING_SO table x3 census clone; bypass HOOK seam banked (witness_18f + Rust bypass-param family), tunnel_decap NOT a codec face (4 packet_manager hits cited); 2 sids ALREADY resident; ZERO new DECODE ids; ZERO gate, ZERO dialect | **closes the misc/ tail cheapest-first**; the trio was ALREADY listed in the tail since 18h; the user DAQ seam is the ONLY unbankable risk — MEASURE at PLAN-0, witness-stub route banked; llc + vxlan = the zero-fresh-cp face for 2/3 of the row. |
| **(b) plan-order: ip/ipv4 + ipv6 + tcp heavyweight trio** | 790 + 733 + 839 = **2,362 L** (re-wc THIS pass, zero drift) | daq.h graft RE-APPLY (tracked file, NEVER re-authored — the reapplied-window face the 18j tripwire watches); the lineage's ONLY witness-STUB RETIREMENT at vocab witness_stubs.cc :11-:13 (cd_ipv4/cd_ipv6/cd_tcp, grep re-cited 18i), per-LINK retirement (18a corollary) + E6 inverted mechanics; likely SPLIT 2-3 commits; tcp.h rides (banked at 18j) | plan fidelity + clears the landmine family; the retirement is the riskiest face in the backlog. NOT pre-decided. |
| (c) trio FIRST then heavyweights (18k = (a), 18l+ = (b)) | 498 then 2,362 | trio cheapens the docs cadence, banks the daq_common/sfdaq witness shapes for the user->row-20 chain AND tcp.h for cd_tcp | honest sequencing story: every later row rides more residency; PLAN-0 at 18k decides (a) vs (b), NEVER pre-decided by THIS pass. |
| (d) detour `src/main/thread_config.cc` | **920 L** | **14** `TEST_CASE` grep-counted at 18h pass (needs the GRE gate shape + hwloc witness ladder, 17l; eth excision carry); breaks codec continuity + donor chain | Fallback ONLY if row 18 stalls (18a/18c/18d/18f/18h ruling — re-affirmed). |

### Rules forward from 18j
- **Git-face rules (the 18i law, the 18j HELD face)**: ONE commit +
  ONE push each; post-push fixups = follow-up commit; face-agnostic
  guard regex (miscip build.sh clone of daq3 :660-688); NO own-HEAD
  pins in harnesses. The 18j reflog shows the cadence works — do NOT
  be the row that tests it again.
- The two-lineage census (**25 holders / 9 x 4826fc22 / 17 distinct —
  MEASURED direct THIS pass; `git ls-files 'tools/*/gate.txt'` = 1**)
  is the LIVE face; NEVER re-pin the arithmetic without measuring THAT
  pass (17p). 18k clones the miscip ZERO-gate face + its census loop.
- 18k rows are ZERO-gate material (0/0/0 above) -> probe-only harness
  clones the MISCP pattern (lineage head) on the miscip copy tree
  (105 post-strip; add ONLY what PLAN-0 measures fresh — the user
  candidates are MEASURED candidates, NEVER pre-type the count). A
  rider daq.h RE-APPLY (option b) rides the TRACKED daq3 graft face +
  must keep the second-landing census honest (same-window exception
  face, the miscip tripwire wording is the template).
- A row that DOES ship real Catch material (thread_config fallback,
  row-19 detection) clones the GRE gate shape: shim passthrough +
  catch_main heredoc + TRACKED gate.txt md5/wc/tail-wording pin +
  rfind/cut-to-EOF excision + E9 dup flipped-assert.
- TRUE-NAME DRIFT rule RE-ARMED: every landing row sed's the TABLE
  (`const BaseApi\* \w+\[\]`) not just the file base + pins the ifdef
  face when the table hides under BUILDING_SO (the misc/ family NOW:
  three pair arms + trio arms :190/:124/:158, ALL measured); Rust
  ladder/file pairs get tripwire tests. Scoping greps pin SYMBOLS not
  substrings (the 18h peg-vs-hook lesson; 18k pins:
  `tunnel_bypass_enabled` HOOK rides vxlan, `tunnel_decap` NEVER does
  — 4 packet_manager-only hits cite).

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — find+wc sweeps re-run THIS docs pass, zero drift)
- Whichever lands next, the 2 daq.h riders trio ipv4 **790** / ipv6
  **733** / tcp **839** (wc re-run THIS pass) carries the ONLY witness-
  stub retirements: vocab witness_stubs.cc :11-:13 cd_ipv4/cd_ipv6/
  cd_tcp tables get REAL replacement, PER-LINK (18a corollary), via the
  E6 inverted mechanics + 3-face census discipline. All THREE carry
  `#include <daq.h>` — the 18i graft is banked for them.
- Then the link tail (wc ALL RE-RUN THIS pass: mpls **390** / vlan
  **236** / pppoe **243** / erspan2 **145** / erspan3 **147** /
  ciscometadata **235** / fabricpath **187** / trans_bridge **158** /
  ppp_encap **174** = **1,915**; **cd_vlan.cc ALSO `#include <daq.h>`**
  — graft-RE-APPLY rider face like the heavyweights), after the 18k
  misc trio if (a)/(c) lands it; nothing else remains in misc/ after
  18k (ls THIS pass: default/geneve/gtp/teredo/icmp4_ip/icmp6_ip/llc/
  user/vxlan — the first six ALL landed rows).
- The 39-extern census + the STATIC_CODEC_EXTERN_NAMES tripwire give
  every row its completeness checklist (ALL queue names ALREADY
  resident codec_api.rs :97-:131 — rows only ADD real TUs, NEVER touch
  codec_api.rs).

## Backlog (plan rows)
- 17z/18a/18b/18c/18d/18e/18f/18g/18h/18i: DONE — wiki trios ALL
  LANDED (18h = 2fdaaae, 18i = **7d623fc** verified THIS pass: status
  row `Porting-status.md:99` + chapter note `:109` + deviations header
  `Deviations-from-Snort-3.md:2029`, grep 'row 18i' = 3 hits).
- 18j: **DONE (76c1c16 — 14 files +2,530/-0 live face, ZERO message
  drift found THIS pass; single reflog `commit:`, single push, origin
  == HEAD = the no-amend rule HELD first try)** — codecs misc icmp-IP
  pair, THE hidden-BUILDING_SO-table row: `misc/cd_{icmp4_ip,icmp6_ip}.cc`
  345+162 = **507 L** literal -> `src/codecs/{cd_icmp4_ip,
  cd_icmp6_ip}.rs` 529+241 = **770 L FLAT** + mod.rs wiring ONLY
  (framework/codec.rs + parse_conf.rs + codec_api.rs + codec_module.rs
  BYTE-UNTOUCHED; ladder :113/:115 turned loaded, `[&str; 34]` face
  pinned by the row build EVERY build; ZERO new sids — six events ride
  codec_module.rs:125-:130); `tools/miscip_harness` NOW LINEAGE HEAD
  (exactly **7** tracked files incl tracked witness_miscip.cc
  `c5b498ff`; ZERO-gate face ENFORCED; tracked gate face still
  ls-files-1; two-lineage census **UNDISTURBED MEASURED THIS pass:
  25 / 9 x `4826fc22` / 17 distinct**); tcp.h 211 L `a7ac7b82` the
  ONLY fresh cp (BANKED for the cd_tcp row); witness delta MEASURED
  **+1** (get_proto_name(IpProtocol) ONLY, the typed +2 HALF WRONG
  recorded honestly, the ProtocolId-overload census 0/0 pin; packet_
  manager.cc 1,047 L find-0 NEVER compiled, provider queued row 20;
  the REAL-body witness rc1 -> the cited-minimal fixed-string witness
  honest face); copy tree 103 donor + 1 fresh hdr + 2 TUs = **106 mid-
  build -> 105 POST-STRIP MEASURED** (daq graft NEVER stays, the E4
  nodaq survivor walls x2 PROVE the DAQ-free split); vectors DEC 23 L
  `43b259ac…` + FACE-A 11 L `e4c47bac…` IMMUTABLE, FRESH x2 rc 0 logs
  **byte-ident THIS pass**, O0==O2 BOTH faces; `tests/miscip_parity_
  test.rs` 636 L 8 tests = 23/23 + 11/11 ORDERED replays + hidden-
  table tripwire + record-census + dialect-census (4/3/3 = 10 names,
  ZERO new translations) units; suite **565 / 0** THIS pass (68 result
  lines); clippy forced relint 0; GROUND-DEAD cc:78 + the cc:108
  switch oddity + the ground-stale encode() comments + the uint16 wrap
  all transcribed literal w/ pins (deviations :3346-:3520 = 175 L /
  15 bullets VERIFY-GREPED count 1); plan row (PORTING_PLAN.md:89)
  VERIFY-GREPED count 1; ritual self-pin DIED at NO row — the face-
  agnostic guard + ground re-pin clone survived the landing (18i
  lesson APPLIED). **Wiki trio for 18j OWED** (next WIKI phase;
  `grep -rn 'row 18j' /tmp/RustyPig.wiki` = 0 hits THIS pass; wiki
  HEAD 7d623fc stops at 18i).
- 18: codecs — 18b-18j DONE; 18k = the misc trio (a) vs the heavyweight
  trio (b) — MEASURED alternatives above, PLAN-0; queue continues per
  order above.
- 19: detection option engines (tree face re-stands from prior passes:
  52 .h+.cc files, 14,533 L; ~47 real Catch TEST_CASE faces — the GRE
  gate shape banked); 20: packet_io / DAQ (AF_PACKET via libc; the 17d
  RawData/daq_msg deferral + the daq graft families close HERE — the
  18i graft + witnesses + the 18j get_proto_name provider queue + the
  18k user.cc SFDAQ seam (if (a)/(c) lands it first) all cite row 20's
  real SDK face); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
   (status MUST be EMPTY; NEVER amend/force anything — the 69c8b6f
   orphan face: if it EVER reappears as an ancestor something is
   WRONG, it must stay merge-base rc 1 against origin/master).
2. `cd tools/miscip_harness && bash build.sh` **x2** -> `MISCIP_HARNESS_OK
   vectors=23 faceA=11 gates=0` + vectors `43b259ac…` / FACE-A
   `e4c47bac…` md5 pins byte-ident across BOTH fresh runs (LOGS cmp
   byte-ident) + the E4 stripped-tree arms + staged-L1 undefined-
   EXACTLY-1 echo + the frozen census echo `9/25 holders of 4826fc22,
   17 distinct` + the nm census echo `icmp4_ip=18 icmp6_ip=10 union=18
   (tunnel_bypass 0/0)` + the mid-106/post-105 find-count echo.
   `cd tools/gre_harness && bash build.sh` x2 for the GATE anchor
   (`GRE_HARNESS_OK vectors=26 faceA=5 gate_lines=3`, gate `6751d1a8`,
   tail `1 assertion in 1 test case`). Rebuild `tools/fmod_harness` for
   the FROZEN-chain byte-ident echo (rc 0, gate `4826fc22`, vectors
   `f0fdbab`) AND `tools/vocab_harness` (rc 0, `VOCAB_HARNESS_OK
   vectors=29`). Verify the frozen lineage by DIRECT md5s (miscip/daq3
   `43b259ac`/`e4c47bac` + `fd1855e1`/`2fb9dc45`, small4
   `462f0ff6`/`4755d48c`, tun `2a792479`/`81602890`, ext `da218429`/
   `0fa79b53`, eth `1bd98dbb`, csum `e4baf781`, witness census
   `9fad7e9d`/`be9bdd0b`/`f4afd35f`/`ea1f79f3`/`4dd91018`; daq3/tun/
   eth/ext NO LONGER chased to rc 0 — by-design drift faces — NEVER
   edit frozen scripts).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test`
   (zero FAILED; >= 565) + clippy 0 -> `.gitignore` block +
   `git check-ignore` -> commit+push (**ONE push, then done — fixes
   ride follow-up commits**; verify `git ls-remote` matches HEAD
   BEFORE any further commit) -> plan row (grep-guard) -> deviations
   append (grep-guard; 18b-18j variant: verify-grep if shipped with the
   code commit) -> refresh THIS file -> commit+push docs -> wiki
   (status row + deviations + stats line — queue: the 18j trio ONLY).
