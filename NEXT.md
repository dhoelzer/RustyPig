# NEXT.md — takeover context & plan (2026-11-20, post-18h: ip small four landed; donor = small4_harness, ZERO-gate head)

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

Current state (measured at this 18h verify-mode docs pass): plan rows
1–18h DONE. **105 commits at HEAD 47654b3** (`git rev-list --count
HEAD` THIS pass; this docs commit lands as the **106th**). **549 tests
green / 0 FAILED** (full `cargo test` re-run AT THIS docs pass: summed
`test result` lines = 549 passed / 0 failed over 66 result lines; 549 =
541 at 18g + 8 `tests/small4_parity_test.rs` (`grep -c '#\[test\]'` = 8
re-measured THIS pass); `FAILED|panicked` grep 0; the four new TUs
`src/codecs/{cd_esp,cd_frag,cd_pgm,cd_auth}.rs` carry ZERO in-crate
`#[test]` (grep 0/0/0/0 re-run THIS pass); `cargo clippy
--all-targets` **0 warnings** (forced relint THIS pass: touched every
.rs, `Finished` line x1, `grep -c '^warning'` = 0), 46,916 lines Rust
across 145 `src/*.rs` files (`find src -name '*.rs' -exec wc -l {} +`
THIS pass), 39 `tests/*_parity_test.rs` whole-transcript replay tests,
410 tracked files (`git ls-files | wc -l`), 46 `tools/*_harness` dirs.
GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the public
status doc (clone at `/tmp/RustyPig.wiki`, remote `RustyPig.wiki.git`,
HEAD **313aab6 = row 18g wiki trio LANDED** — verified read-only at
this docs pass: `git -C /tmp/RustyPig.wiki log -1` prints `313aab6 row
18g: status + deviations + stats (103 commits / 399 files / 45,902 src
lines / 541 tests ...)` and the 18g trio greps PRESENT
(`Porting-status.md:97` status row + `:105` chapter note +
`Deviations-from-Snort-3.md:1742` deviations header — the EARLIER NEXT
edition's "wiki stops at 18f / d13ccca, the 18g trio OWED" line is
SUPERSEDED by this measurement: the trio LANDED as measured; this docs
pass touched the wiki ZERO times). **The 18h wiki trio is OWED** and is
owed at the NEXT WIKI phase, not by this docs pass (`grep -rn 'row 18h'
--include='*.md' /tmp/RustyPig.wiki` — also `small four` / `cd_esp`
variants — = **0 hits** verified THIS pass). The owed trio = status row
(ip/cd_esp+cd_frag+cd_pgm+cd_auth, 800 L ground -> 1,002 L Rust + 802 L
replay test; THE ZERO-gate 16th-straight face: no gate.txt added,
two-lineage census 9/25/17 UNDISTURBED, THE cd_ah name-drift headline
IN the transcript) + the row-18h deviations section (copy from KNOWN
DEVIATIONS.md :3015-:3186) + stats line ("106 commits / 410 tracked
files / 46,916 src lines / 549 tests" — LIVE values at THIS docs pass,
re-measure at the wiki pass before typing).

## 18h close-out — VERIFY MODE (plan row + deviations shipped WITH code commit 47654b3; this pass greps-verify + re-ground rather than append)
Like 18b-18g, 18h's plan row and deviations section shipped inside the
CODE commit, so this docs pass is a verification pass. Everything below
was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18h |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:87) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what 47654b3 shipped (`git show
  --stat 47654b3`: **15 files changed, +2,804 / -1** — EXACTLY 15
  staged paths: 6 harness files + 4 src TUs + mod.rs + parity test +
  .gitignore + plan + deviations — plan-first staging face).
- **Deviations section**: `grep -c '^## codecs ip small four (row 18h'`
  = **1** at **:3015**, running to EOF at **:3186** = **11** bullets
  (`grep '^- \*\*'` count THIS pass). **Verdict:
  ADEQUATE-READ-LEAVE** — the ZERO-gate census disclosure, the INVERTED
  E4 residency arms, the cd_ah name-drift tripwire family, the
  row-scoped DecodeData seams, the const_cast fold, the pgm offset-read
  posture, the sids ZERO-new census and the clippy face all re-grounded.
  **TWO honest count/anchor drifts recorded this pass** (land rule:
  rows/sections/messages NEVER rewritten, no force-push): (1) the
  47654b3 message says deviations at "KNOWN DEVIATIONS.md:3014-:3186,
  173 L" — live face: header at **:3015** (blank separator :3014),
  :3015-:3186 = **172 L**; the "11 bullets" face MATCHES exactly. (2)
  A block of internal line-cites inside the deviations section was
  drafted against an earlier build.sh revision and runs ~13-31 lines
  stale vs the FINAL committed 453-L build.sh: the census loop cited
  ":455-:459" is LIVE at **:442-:452**; `test ! -e gate.txt` cited
  ":203-:205" at **:233**; the nm one-table-symbol-per-.o census cited
  ":211-:216" at **:240-:241**; tunnel_bypass 0/0/0/0 cited
  ":225-:229" at **:247**; wc 46/17 pins cited ":438-:443" at
  **:407-:408**; enable_esp grep ":369" at **:373**; RuleMap census
  ":357-:360" at **:362-:366**; decimal hygiene ":303-:304" at
  ":302-:303**; the "grep 0 x14" landmine loop cited ":86-:90" is
  LIVE at **:91-:94** (7 names x 2 donors = 14 grep arms). The cites
  that HOLD exactly: ground
  md5+wc x4 :38-:45, ground md5 declares :39-:40 + wc face :41,
  table-arms x4 :54-:61, cd_ah sed-pin :61, cd_ah extern-pin :65,
  drift tripwire :74-:77, ah_api :79 + CD_AUTH_NAME :80, frag rider
  :83, ladder pins :85-:88, 39-extern census :89, copy-count 96 :125,
  E4_nochecksum_pgm
  :146-:150, E4_notextlog_frag :156-:159, restored rc0-x4 :161-:165,
  witness_conf md5 pin :213, O0==O2 + drift-then-refuse :294-:297.
  Both drifts are cite-arithmetic of the scoping passes, NOT behavioral
  claims — every behavioral claim below re-verified independent.
- **Harness FRESH x2 THIS pass, rc 0 both runs**: `SMALL4_HARNESS_OK
  vectors=46 faceA=17 gates=0` tail verbatim, LOGS byte-ident run A vs
  B (`cmp` rc 0, receipts `/opt/data/cache/scratch/row18hdocs/small4_{A,B}.log`).
  md5 pins ALL re-summed byte-exact THIS pass: vectors.txt 46 L
  `462f0ff6ed44220564c5ef0c8538ad80`, vectors_faceA.txt 17 L
  `4755d48c54cc057b3c3c9eafec01c7cf`; the 6 tracked faces re-md5'd:
  build.sh 453 L `2e69808067c40238de7413cb471c7db0`, PLAN.md 73 L
  `660231495c583253f03fd3989b809b13`, probe.cc 37 L `25790ae9...`,
  probe_dec.cc 163 L `00ce81c1...`. Ground identity re-measured:
  esp/frag/pgm/auth wc **227/190/211/172 = 800** + tables
  `cd_esp[]` :221 / `cd_frag[]` :184 / `cd_pgm[]` :206 / **`cd_ah[]`
  :166** (`grep 'const BaseApi\* cd_'` re-sed ALL FOUR THIS pass);
  ladder cd_ah :98 / cd_esp :105 / cd_frag :108 / cd_pgm :121 resident
  codec_api.rs (`grep -n` THIS pass); `grep -rn 'extern const BaseApi\*
  cd_auth\b' /opt/data/snort3-src/src` = **0 hits** THIS pass — the
  drift tripwire's inverted arm still stands; the transcripts STILL
  CARRY the drift: vectors_faceA:2 `LOAD ipv6_frag`, :4 `LOAD auth`,
  :15 `API ah type=0 size=112 ver=1900547 name=auth` (grep THIS pass).
- **ZERO-GATE ARTIFACTS — face ENFORCED, not assumed, and census
  UNDISTURBED**: small4 carries NO gate.txt / catch_main / -DUNIT_TEST
  face (`test ! -e "$H/gate.txt"` LIVE at build.sh :233; the 6 tracked
  files re-confirmed by `git ls-files` THIS pass = PLAN.md build.sh
  probe.cc probe_dec.cc vectors.txt vectors_faceA.txt). Two-lineage
  census MEASURED at this docs pass OUTSIDE the harness too:
  `ls tools/*/gate.txt | wc -l` = **25**, md5 holders of
  `4826fc22...` = **9**, distinct md5s = **17**
  (md5sum|sort -u|wc -l THIS pass — SAME face the row's own loop prints
  at :442-:452: "frozen census: 9/25 holders of 4826fc22, 17 distinct
  md5s ... tracked gate.txt = 1, ls-files"); `git ls-files
  'tools/*/gate.txt'` = **1** (gre's — still the only tracked gate).
  small4 added ZERO gate files: 18h = the 15th straight honest
  zero-gate face. **Frozen lineage re-verified the sanctioned way** —
  direct md5 re-sums, frozen donors NOT chased to rc 0: tun vectors
  `2a792479` + faceA `81602890`, ext `da218429`/`0fa79b53`, eth
  `1bd98dbb`, all ZERO drift THIS pass; 5-fingerprint witness census
  re-md5'd byte-exact: vocab witness_stubs.cc `9fad7e9d...`, codec
  stubs.cc `be9bdd0b...`, eth stubs_18d.cc `f4afd35f...`, tun
  witness_18f.cc `ea1f79f3...`, witness_conf `4dd91018...` (build.sh
  :213 pins the heredoc regen byte-ident).
- **Gate chain frozen side — MEASURED not asserted**: gre rebuilt
  FRESH x2 THIS pass rc 0 BOTH (`GRE_HARNESS_OK vectors=26 faceA=5
  gate_lines=3`, logs byte-ident, gate `6751d1a8` + vectors
  `41bd7d1b`/`783649440d` all re-md5'd byte-exact, runner tail VERBATIM
  re-grepped `All tests passed (1 assertion in 1 test case)`); fmod
  FRESH rc 0 (`FMOD_HARNESS_OK vectors=61`: gate `4826fc22...` +
  vectors `f0fdbab...`, gate.txt tail re-read VERBATIM `All tests
  passed (114 assertions in 22 test cases)`); vocab FRESH rc 0
  (`VOCAB_HARNESS_OK vectors=29`, vectors `5da70e82...` stable). csum
  vectors `e4baf781` re-md5'd face. Receipts
  `/opt/data/cache/scratch/row18hdocs/{gre_A,gre_B,small4_A,small4_B,fmod,vocab}.log`.
- **Rust-side anchors re-grounded THIS pass**: `src/codecs/cd_esp.rs`
  292 + cd_frag.rs 269 + cd_pgm.rs 213 + cd_auth.rs 228 = **1,002 L**
  (wc THIS pass); `tests/small4_parity_test.rs` **802 L / 8 `#[test]`**
  (wc + grep THIS pass — 46/46 + 17/17 ORDERED replays +
  `small4_static_names_tripwire` pinning names[0]=="cd_ah" +
  `!contains("cd_auth")` + file-vs-NAME pairs; NO `up_gate_*` — honest
  zero-suite absence); sids 272/294/454/456/458/459/465/466 ALL
  resident codec_module.rs (`grep -n` THIS pass :133-:224 — ZERO new
  constants); framework/codec.rs + parse_conf.rs + codec_api.rs
  BYTE-UNTOUCHED; the 39-extern cc census pinned AGAIN by the row
  build (`grep -c 'extern const BaseApi\* cd_'` == 39, build.sh :89).
- **Test math**: 549 = 541 + 8; plain `cargo test` 66 result lines,
  FAILED/panicked grep 0, at THIS pass; 39 parity files (38 + small4).
- **Landmine face for the 18h names — substring honesty recorded**:
  bare-substring greps hit noise (`esp` 1/2, `frag` 0/3) — the hits are
  `layer::get_inner_ip6_frag` FUNCTION stubs (codec stubs.cc :20-:21)
  and `using namespace snort` lines, NOT tables; the TABLE-name grep
  `cd_esp\b|cd_frag\b|cd_pgm\b|cd_ah\b` across vocab witness_stubs.cc +
  codec stubs.cc = **0** THIS pass (and `cd_udp|cd_icmp4|cd_icmp6` =
  0/0 each, substring-covering the *_ip variants). Landmine ZERO
  stands for the whole 18i candidate set.
- **commit census + gitignore**: 105 at HEAD 47654b3; .gitignore small4
  block :420-:441 re-verified by `git check-ignore` THIS pass
  (`tools/small4_harness/copy/` hits at :423; binaries .o witness_conf.cc
  vectors_O0/O2 nm_U_* E4_* drift_cd_auth_extern md5_pinned
  gate_md5_lineages cp_audit_ok .e4_hold_*.log all ignored rc 0; the 6
  stageables NOT ignored). `git status --short` **EMPTY** (wc 0) after
  the docs-pass rebuilds — artifacts fully absorbed.
- **Scoping-claim correction (the method proving itself AGAIN)**: the
  18g-pass NEXT line "**cd_udp/cd_icmp* decode paths ride the same
  tunnel_bypass seam**" is HALF WRONG — re-measured THIS pass:
  `grep -c tunnel_bypass` over cd_udp/cd_icmp4/cd_icmp6 = **0/0/0**
  (contrast gre x1). What the trio actually carry: a per-TU
  `checksum_bypassed` PEG + `stats.cksum_bypassed++` (udp :49/:57/:274,
  icmp4 :45/:52/:143, icmp6 :47/:54/:136) and udp :501's tunnel
  COMMENT — the tunnel_bypass HOOK face does NOT extend to the trio.
  Consequence measured: at 18i the trio expect **ZERO new witnesses**
  on the bypass axis (the WIN trio rides), and the cksum-bypass pegs
  are row-local stats material. Lesson: peg-name vs hook-name greps are
  different faces — pin the symbol, not the substring.

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript. vectors.txt is a tracked
   INPUT the build re-verifies but NEVER fabricates (18d lesson; small4
   adds the FIRST-RUN-SEED then drift-then-refuse face at :296-:297).
2. **Catch gate** whenever upstream ships an embedded
   `#ifdef UNIT_TEST` block or a `test/` suite: compile it verbatim
   (`catch/snort_catch.h` -> plain-catch shim; the FRESHEST working
   shape stays at GRE: `tools/gre_harness/build.sh` :132 catch.hpp cp +
   :139 catch_main.cc heredoc + :143 CATCH_CONFIG_MAIN pin, plus fmod
   :249/:270 and fctx :60-:63/:403-:407 for the older carries;
   TestCaseInstaller route REJECTED at 18g, deviation :2928-:2939). Run
   it; record cases/assertions in `gate.txt`; an embedded-Catch codec
   row's gate.txt is TRACKED with pinned md5 + wc + the runner's own
   tail wording (the gre pattern). NEVER gate on grep-estimated
   assertion counts — pin case names/counts from grep, measure
   assertions from the runner (17p). When gate and probe link the same
   TU, use the **duplicate-symbol rule** (E9 face at gre). Zero-suite
   rows run the **small4 ZERO-gate face**: `test ! -e gate.txt` + NO
   Catch symbols asserted IN the build — the absence is enforced, not
   assumed — and the two-lineage census loop (9/25/17-style, :442-:452)
   lives in the NEWEST harness and MEASURES (18h = 15th straight). The
   17y INVERSION lesson, the 18a PER-LINK corollary, the 18b PROBE-ONLY
   corollary, the 18d INVERTED-DUP face, the 18e FACE-RULE and the 18g
   TWO-LINEAGE codification (frozen donor rows are historical
   artifacts, NEVER rewritten; their point-in-time `-eq 24` ls-asserts
   fail BY DESIGN — deviation :2921-:2927) all stand. A fake Catch gate
   over a suite-zero row = the 17p anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced and every one gets a section
   in `KNOWN DEVIATIONS.md`. 18h reinforcements: name-drift folds keep
   the FILE base true while the Rust table constant mirrors the C TABLE
   (`CD_AH`/`AH_API`), and dead ground code (`#if 0` DECODE_RF, the
   cc:167 >0xFF arm) stays dead-but-cited, NOT excised.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-index assert, ORDERED, never set-membership),
   donor pattern: `tests/small4_parity_test.rs` (802 L, 8 tests, the
   name-drift-IN-transcript + tripwire face, honest zero-suite absence),
   `tests/gre_parity_test.rs` (723 L, 11 tests — the pattern for GATE
   rows: runner-tail pin + `up_gate_*`), `tests/tun_parity_test.rs`
   (860 L, 9 tests, DUAL-face for multi-face zero-suite rows),
   `tests/eth_parity_test.rs` (608 L), `tests/vocab_parity_test.rs`
   (442 L), `tests/csum_parity_test.rs` (414 L).
5. **Gates at EVERY commit**: `cargo test` all green (>= 549; never
   trust a summed total from a run containing FAILED; cite one face per
   pass), clippy --all-targets ZERO warnings (force relint by touching
   all .rs), `vectors.txt` md5 stable across >= 2 clean rebuilds
   (small4's FRESH x2 logs byte-ident THIS pass), harness `.gitignore`
   block added (mirror siblings) and verified with `git check-ignore`
   BEFORE staging (the small4 block is .gitignore:420-:441, landed
   inside code commit 47654b3). Then commit + push, insert the plan row
   (grep-guard: count must be 0 before insert), append deviations (one
   grep-guarded append) — the 18b-18h variant: BOTH ship inside the
   code commit, then the docs pass VERIFY-greps them (count == 1 each)
   and still re-measures every load-bearing claim. Refresh NEXT.md
   (FRESH rewrite), commit+push docs. Wiki: status row + deviations
   section + stats line at the WIKI phase — queue status measured at
   THIS pass: 18g trio is LANDED (313aab6), the ONLY owed trio is 18h.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. 17s/18b-18h do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH; nm pin fmod build.sh:961). Row-TU lua-seam assert carried every build since 18d.
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum/vocab/eth/ext/tun/gre build: E4_cpputest_fatal flipped-assert EVERY build, plus the checksum_test.cc:36 precedent — `ip/test/` is CppUTest dialect ONLY). Upstream CppUTest suites can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp `74ef54e8` + shim) runs natively — banked at 18g: the cd_gre gate ran REAL. **ip/checksum.h DONOR-RESIDENT** (`b43628f3` ground face): pgm rode it at 18h as the SECOND rider (18g was the first). `log/text_log.h` `3e827113` resident via the tun lineage — frag the first rider at 18h.
- **`#include <daq.h>` does NOT exist in ground — find PROVEN WIDER THIS pass** (whole-repo `find /opt/data/snort3-src -name 'daq.h'` = 0 hits; NEVER confuse: `daqs/daq_user.h` 54 L lives OUTSIDE src/, `src/pub_sub/daq_message_event.h`, and the `src/packet_io/sfdaq*.h` family are ALL different faces; `find tools -name 'daq.h'` = 0 — no graft has ever been landed). The 18i trio's `#include <daq.h>` at cc:25 x3 is THE open question — see the 18i scoping below. The fmod `daq_common.h` (16 L graft face — it rides INSIDE the copy trees: `find tools -name daq_common.h` hits) + vocab `daq_dlt.h` (5 L) graft precedents are the only stand-in pattern. esp/frag/pgm/auth carried NO daq include (18h face, re-pinned by the SMALL4 build compiling the four with ZERO fresh cps).
- **daq_dlt.h graft IS a committed fact**: `tools/vocab_harness/copy/daq_dlt.h` + the eth/gre/small4 copy carry `DLT_RAW 12` / `DLT_EN10MB 1` / `DLT_PPP_ETHER 51` (libpcap master cites). Later rows cp/extend THAT graft; row 20 cites the real DAQ include chain.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 + 18d-18h replay mirrored Rust-side; small4 probe_dec keeps the same shape — Rust side stores every bool before field reads).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY. Since 18a `file_trace` has its REAL def on BOTH sides.
- Frozen-donor build.sh rc-1 face (the 18g drift codified): tun/eth/ext die at their point-in-time `-eq 24` gate.txt ls-asserts (tun :334, eth :598, ext :320) since gre added the 25th gate — BY DESIGN, NEVER edit frozen scripts; verify their frozen face by DIRECT vectors md5 re-sums (re-done THIS pass: tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`, eth `1bd98dbb` — all byte-exact).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/small4_harness/` — **THE donor for row 18i+ (lineage head, ZERO-gate shape)**: exactly **6** tracked files (build.sh 453 L md5 `2e698080...`, PLAN.md 73 L `6602314...`, probe.cc 37 L `25790ae9...`, probe_dec.cc 163 L `00ce81c1...`, vectors.txt 46 L `462f0ff6...` tracked, vectors_faceA.txt 17 L `4755d48c...` tracked; NO gate.txt, NO catch_main — the gre-8 face MINUS the two gate faces; NO witness FILE — the WIN trio INHERITED: witness_18f `ea1f79f3` + witness_conf heredoc `4dd91018` (pin :213) + stubs_18d `f4afd35f`, md5 pins NEVER re-derived); copy tree = gre DONOR VERBATIM (`find copy -type f ! -name '*.o'` = 92 pre-row, gre face re-counted THIS pass) + EXACTLY 4 row TUs + ZERO fresh headers = **96** post-cp find-count asserted at :125. Self-checks re-run THIS pass at BOTH fresh rebuilds (rc 0 logs byte-ident): ground md5 x4 + wc x4 :39-:45; table sed census x4 :54-:61; cd_ah :61 / extern :65 / drift-tripwire DIES-IF-HIT :74-:77; ladder sed pins :85-:88; landmine grep 0 x donors :91-:94; 39-extern census :89; E4 INVERTED residency arms (strip checksum.h -> ONLY pgm dies cc:28 :146-:150; strip text_log.h -> ONLY frag dies cc:26 :156-:159; restored rc0 x4 :161-:166); NO-gate face :233; nm one-table-symbol-per-.o :240-:241; tunnel_bypass 0/0/0/0 :247; O0==O2 x2 streams + FIRST-RUN-SEED drift-refuse :294-:297; decimal hygiene :302-:303; sids x8 tie :92-:107; RuleMap census :362+; enable_esp NSDMI :373; wc 46/17 :407-:408; TWO-LINEAGE census loop :442-:452 (9/25/17 + tracked-1 FACE). Probe loads pull NO codec_api object (nm union grep load_codecs 0 THIS pass).
- `tools/gre_harness/` — **THE gate-shape donor (18g; kept for ANY row with real Catch/Catch-suite material)**: exactly 8 tracked files, gate.txt 3 L md5 `6751d1a8` TRACKED (tail `All tests passed (1 assertion in 1 test case)`, pins :378-:382), vectors `41bd7d1b` 26 L + faceA `783649440d` 5 L, build.sh 412 L md5 `de698f47...`, anchors :43-:49, catch shape :132/:139/:143, E9 dup flipped-assert, rfind+cut-to-EOF excision, census loop :401-:404 (9/25/17). Rebuilt FRESH x2 THIS pass, rc 0, logs byte-ident.
- `tools/tun_harness/` — the 18f ancestor (7 tracked files; its `-eq 24` census line rc-1 fails by design — see drift face): DUAL-face vectors 40L `2a792479` + 7L `81602890` re-md5'd ZERO drift THIS pass (direct md5s), witness_18f.cc `ea1f79f3`, nm U-census arms 10/24/42. NO tracked gate.
- `tools/ext_harness/` — the 18e ancestor (7 tracked files): DUAL faces 27L `da218429` + 9L `0fa79b53` re-md5'd zero drift THIS pass. `-eq 24` face dead by design. NO tracked gate.
- `tools/eth_harness/` — the 18d ancestor (5 tracked files): stubs_18d.cc `RETIRED at 18d` marker md5 `f4afd35f` — carried by every later row; vectors 15L `1bd98dbb` re-md5'd zero drift; EXTENDED `daq_dlt.h` graft; lua-seam assert. NO tracked gate.
- `tools/vocab_harness/` — the 18c ancestor (rebuilt FRESH THIS pass rc 0, `VOCAB_HARNESS_OK vectors=29`): witness_stubs.cc 14L `9fad7e9d` — the 4 cd_ipv4/ipv6/tcp/hopopts stub tables :11-:14 frozen by vectors:25-:28; ZERO 18h/18i table stubs (re-grepped THIS pass); vectors 29L `5da70e82` stable; the `daq_dlt.h` GRAFT originated here.
- `tools/fmod_harness/` — the 18a donor & **FROZEN gate-lineage source** (rebuilt FRESH THIS pass rc 0 `FMOD_HARNESS_OK vectors=61`, gate `4826fc22` tail VERBATIM `All tests passed (114 assertions in 22 test cases)`, vectors `f0fdbab`): cp braces + objs loop carry the FULL file_api closure; first third-party link (`libluajit.a` BY PATH, nm pin :961); catch-recipe carry :249/:270 (fctx :60-:63/:403-:407 the older full shape); daq_common.h 16 L graft home.
- `tools/csum_harness/` — row 18b, the probe-only origin: build.sh ground-header md5 pin :37, E4 wall receipt :67-:70, dialect proof :72-:73, nm ZERO-text-symbols :79-:80, O0==O2 :116, census :154, vectors 16L md5 `e4baf781`. `ip/checksum.h` enters DONOR trees via gre's cp — pgm rode it at 18h; udp/icmp4/icmp6 inherit the residency.
- `tools/flog_harness/` (17z): vectors 50L `b260ec6a`. `tools/fsvc_harness/` (17y, landmine inversion): 64L `54864705`. `tools/fpolicy_harness/` (17x): 27L `b989a8d5`. `tools/finspect_harness/` (17w): 103L `3cbd009e`. `tools/fcapi_harness/` (17v; dir name pinned): 21L `a953a501`. `tools/fconf_harness/` (17u): 20L `65968e1c`. `tools/fcshare_harness/` (17t): 25L `03d43c14`. `tools/fcap_harness/` (17s): 27L `0208a691`; gate `4826fc22` — the frozen chain STARTS here.
- `tools/fctx_harness/` — FileContext + capture/mempool/segment closure donor: vectors 610L `839b5566`; gate `42349372` (own lineage, never joined). `tools/fflows_harness/` vectors 146L `bd8c00af` (DO NOT touch), gate `e14626fc`. `tools/fcache_harness/` vectors 278L `b69db310` (DO NOT touch), gate `6b3c041e`. `tools/filib_harness/` vectors 273L `77ffd8e4` (DO NOT touch), gate 19/334. `tools/fstats_harness/` — the only file_api/ test/ suite. `tools/textlog_harness/` — time() interposition precedent. `tools/rules_harness/` — EOFCFG shim; hosts `copy/catch/catch.hpp` `74ef54e8` (byte-ident gre THIS pass). `tools/fid_harness/` — ghash closure. **`tools/codec_harness/` is row 17d's harness** (framework/codec base; stubs.cc md5 `be9bdd0b...` re-confirmed THIS pass is the FROZEN donor the E6-YES arms re-collide against; ZERO 18h-name table stubs) — the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.

## Next milestone — row 18i: the ip DAQ trio FRESH-measured at the 18h docs pass (udp + ICMP pair; THE daq.h head-on decision; the misc-pair tie-ins)

### The queue face, measured THIS pass (ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY)
- **Gate material: ZERO everywhere**: combined grep
  `TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST` over `ip/cd_udp.cc`,
  `cd_icmp4.cc`, `cd_icmp6.cc`, `misc/cd_icmp4_ip.cc`,
  `misc/cd_icmp6_ip.cc` = **0/0/0/0/0** (loop re-run THIS pass — 18h's
  four files also re-grepped 0 x4) — honest probe-only rows; small4's
  ZERO-gate face (test ! -e gate.txt + census loop) is the clone
  pattern; two-lineage face stands untouched at 25/9/17.
- **THE daq.h face — head-on at 18i** (all cites THIS pass):
  `#include <daq.h>` at cd_udp.cc:**:25**, cd_icmp4.cc:**:25**,
  cd_icmp6.cc:**:25**; the DAQ usage is THIN and MEASURED: **13 lines**
  total across the trio touching EXACTLY 7 distinct symbols —
  `DAQ_PktDecodeData_t`, `DAQ_NAPTInfo_t`, `DAQ_PKT_META_DECODE_DATA`,
  `DAQ_PKT_META_NAPT_INFO`, `DAQ_PKT_DECODE_OFFSET_INVALID`,
  `daq_msg_get_data`, `daq_msg_get_meta` — at udp :263-:270/:420,
  icmp4 :132-:139, icmp6 :125-:132 (+ the same shapes). Absence PROVEN
  this pass WIDER than src: `find /opt/data/snort3-src -name 'daq.h'`
  = **0 hits whole-repo** (only `daqs/daq_user.h` 54 L outside src +
  `src/pub_sub/daq_message_event.h` + `src/packet_io/sfdaq*.h` — NEVER
  confuse); the donor trees carry NO daq.h either (`find tools -name
  'daq.h'` = 0). The seam is HALF-RESIDENT already: `framework/codec.h`
  (inside the copy tree, :38/:59/:63-:64) carries `struct _daq_msg;`
  fwd-decl + the `RawData.daq_msg` member (the 17d deferral face) — the
  trio deref `raw.daq_msg`, so the PLUMBING exists, the TYPES/
  FUNCTIONS do not.
- **UDP heavyweight** `ip/cd_udp.cc` **660 L** (wc THIS pass; path pin
  holds — ip/ NOT misc/): table `const BaseApi* cd_udp[] =` at **:655**;
  extern cd_udp codec_api.cc **:70** + load_plugins **:115**; ladder
  cd_udp resident codec_api.rs:128. Includes cc:22-:36 (sed THIS pass):
  config.h + `#include <daq.h>` :25 + the resident base
  (codec_module.h / framework/codec.h / log/messages.h / log/text_log.h
  / main/snort_config.h / utils/util.h / checksum.h — ALL present in
  the small4 copy tree, find 1 x7 THIS pass) + `protocols/teredo.h` :32
  (**RESIDENT** — find 1 in small4 copy) + `protocols/udp.h` :33
  (ground **68 L**, find vs small4 copy = **0 hits -> fresh cp**).
  Stats face: cksum_bypassed peg :49/:57/:274 (NOT the tunnel hook —
  the 18g correction above) + the :501 tunnel comment.
- **ICMP pair** `ip/cd_icmp4.cc` **645 L** (table cd_icmp4[] **:640**,
  externs **cd_icmp4 :54 + cd_icmp4_ip :55**, load **:99-:100**;
  includes :22-:33: daq.h :25, ALL-FIVE resident base headers,
  `protocols/icmp4.h` :31 (ground **259 L**, small4 copy 0 hits ->
  **fresh cp**), checksum.h :33 RESIDENT) and `ip/cd_icmp6.cc` **518 L**
  (table cd_icmp6[] **:513**, externs **cd_icmp6 :56 + cd_icmp6_ip
  :57**, load **:101-:102**; includes :22-:35: daq.h :25, resident
  base, `protocols/icmp6.h` :31 (ground **196 L**, 0 hits -> **fresh
  cp**) AND `protocols/icmp4.h` :32 (**cross-rider — the ONE icmp4.h
  fresh cp feeds BOTH rows**), utils/util.h resident, checksum.h :35);
  ladder cd_icmp4/4_ip/6/6_ip ALL resident codec_api.rs:112-:115.
  cksum_bypassed pegs per TU as udp (icmp4 :45/:52/:143, icmp6
  :47/:54/:136). Pair completeness bar = the FOUR externs
  (:54-:57): there is NO cd_icmp4_ip/cd_icmp6_ip FILE in ip/ — those
  tables live in `misc/cd_icmp4_ip.cc` **345 L** (table :339) +
  `misc/cd_icmp6_ip.cc` **162 L** (table :157), wc THIS pass; their
  include closures ride the SAME fresh cps (icmp4_ip includes
  protocols/icmp4.h :28 + protocols/udp.h :31 + packet_manager.h :29
  RESIDENT + **protocols/tcp.h :30 — 0 hits -> the pair's ONLY extra
  fresh cp**) — measure at that row whether the misc pair rides INTO
  18i or tails after (a PLAN-0 call, NEVER pre-decided; the extern
  census stays complete only when all 4 names link real).
- **Bypass seam RE-SCOPED (18h correction stands)**: trio tunnel_bypass
  grep **0/0/0** THIS pass -> ZERO new witness expected; the WIN trio
  (ea1f79f3/4dd91018/f4afd35f) rides inherited. The tunnel_mask seam
  (snort_config.h:119-:128 TUNNEL_* table) stays a gre-face cite only.
  Landmine posture **ZERO for every 18i name**: cd_udp / cd_icmp4 /
  cd_icmp6 greps 0/0 in vocab witness_stubs + codec stubs THIS pass
  (substring-covers the *_ip forms); table-name greps 0.
- **STATIC_CODECS extern census**: 39 lines re-counted THIS pass cc
  face (pinned -eq 39 by small4 build.sh :89); ip-region hit-list:
  cd_ah :40 (**LANDED 18h**), cd_esp :47 (**LANDED 18h**), cd_frag :50
  (**LANDED 18h**), cd_gre :52 (**LANDED 18g**), cd_icmp4 :54,
  cd_icmp4_ip :55, cd_icmp6 :56, cd_icmp6_ip :57, cd_pgm :63
  (**LANDED 18h**), cd_udp :70 + the ipv4/ipv6/tcp trio (the last three
  witness-stub owners, retirement rows).

### 18i alternatives — honest comparison (measured THIS pass)
| option | size | fresh-cp / risk face | verdict |
|---|---|---|---|
| **(a) plan order: 18i = udp + icmp4 + icmp6 (the DAQ trio)** | 660+645+518 = **1,823 L** (wc cites above) | fresh cps EXACTLY 3 headers = udp.h 68 + icmp4.h 259 (x1, cross-rides icmp6) + icmp6.h 196 = **523 L** (teredo.h + checksum.h + the whole base RESIDENT, find 1 x7 + 0 x3 above); THE daq.h graft-vs-defer call (table below); trio add 3 externs + 3 ladder names ALREADY resident; 2 probe rows likely (pair + udp) or ONE harness like small4's FOUR-in-ONE (all three closures share the graft — decide at PLAN 0) | **HIGHEST plan fidelity**; the DAQ head-on arrives with the trio anyway AND `link/cd_vlan.cc` + ipv4/ipv6/tcp ALL `#include <daq.h>` too (grep -l THIS pass) — pay the graft ONCE and 4 later rows ride it. |
| **(b) trio + misc pair in one sweep** | 1,823 + 345 + 162 = **2,330 L** | same 3 cp + tcp.h (pair's only extra, 0-hit face above); closes the FOUR-extern pair face (:54-:57) in one commit; gate 0 x2 on the pair; pair closures ride the copy face (codec_module.h/framework/codec.h/... resident per includes :21-:31) | Honest scope-UP option — PLAN-0 at 18i calls size vs one-commit-cleanliness; if (a) lands trio-only, the pair tails as its own row with tcp.h + one cp. |
| (c) detour `src/main/thread_config.cc` | **920 L** | **14** `TEST_CASE` grep-counted THIS pass (needs the GRE gate shape + hwloc witness ladder, 17l; eth excision carry); breaks codec continuity + donor chain | Fallback ONLY if row 18 stalls (18a/18c/18d/18f/18h ruling — re-affirmed). |

**daq.h graft-vs-defer decision table (the row-18i PLAN-0 call, NEVER pre-decided; costs MEASURED THIS pass):**
| face | cost measured | precedent / note |
|---|---|---|
| **graft (minimal `daq.h` in the copy tree)** | 7 symbols above: 2 type names + 3 constants + 2 FUNCTIONS (`daq_msg_get_data` / `daq_msg_get_meta` — these need WITNESS stubs for the link, a NEW cost vs header-only precedents); synthetic `DAQ_PktDecodeData_t` bodies feed the vectors arms (l4_offset face) | fmod `daq_common.h` 16 L + vocab `daq_dlt.h` 5 L are the ONLY graft precedents (both committed facts); reuse banked: vlan + ipv4/ipv6/tcp rows ride it free (`grep -l 'include <daq.h>'` face THIS pass) |
| **defer (row-20 posture)** | CANNOT satisfy compilation: the include is INSIDE the ground TUs and ground C is NEVER trimmed — a minimal header MUST land; what CAN defer is DAQ SEMANTICS: `raw.daq_msg` provenance stays the 17d left-open seam (codec.rs:9/:171 face), meta pointers synthetic in the probe ONLY, real DAQ at row 20 | "defer" therefore = graft-anyway-minimally + defer-semantics; the honest framing for the deviations row — there is no NO-graft option once the trio compiles verbatim |
| **hybrid: reuse `daqs/daq_user.h` (54 L)** | real-ground header, but lives OUTSIDE src/ (include-path + CMake-context faces untested on host; pulls its own deps — UNVERIFIED cost, flag for the PLAN-0 recon) | daqs/ also carries daq_file.c/daq_hext.c impl faces — the most faithful stand-in if it compiles clean; NEVER assume, compile-rehearse in scratch first (the 18h PLAN.md seed pattern) |

### Rules forward from 18h
- The two-lineage census (9 x 4826fc22 frozen + gre's own = 25/17) is
  the LIVE face — re-measured DIRECT this pass (17 distinct md5s,
  md5sum|sort -u). 18i clones the small4 ZERO-gate face and its census
  loop; NEVER re-pin 25/9/17 arithmetic without measuring THAT pass
  (17p).
- 18i rows are ZERO-gate material (0 x5 above) -> probe-only harnesses
  clone the SMALL4 pattern (lineage head) on the small4 copy tree (96
  find-count; add ONLY what PLAN-0 measures fresh — NEVER pre-type the
  count).
- A row that DOES ship real Catch material (thread_config fallback,
  row-19 detection) clones the GRE gate shape: shim passthrough +
  catch_main heredoc + TRACKED gate.txt md5/wc/tail-wording pin +
  rfind/cut-to-EOF excision + E9 dup flipped-assert.
- TRUE-NAME DRIFT rule RE-ARMED (the cd_ah face, now a LANDED tripwire
  face): every landing row sed's the TABLE (`const BaseApi\* \w+\[\]`)
  not just the file base; the Rust ladder/file pair gets a tripwire
  test. 18i table sites sed-cited THIS pass: udp **:655** / icmp4
  **:640** / icmp6 **:513** / icmp4_ip **:339** / icmp6_ip **:157** —
  no name drift found in the trio/pair so far (file base == table base
  for all five; the `_ip` pair's FILE faces already drift from the
  extern region ip/ -> misc/ — cite the paths at the row).
- Scoping greps pin SYMBOLS not substrings (this pass's correction):
  peg-family names (`checksum_bypassed`) are NOT hook faces
  (`tunnel_bypass_enabled`) — grep the exact callee.

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — find+wc sweeps re-run THIS docs pass, zero drift vs the 18g face)
- After the DAQ queue: the 3 heavyweight stub-table owners ipv4 **790**
  / ipv6 **733** / tcp **839** (wc re-run THIS pass); cd_ipv4/cd_ipv6/
  cd_tcp witness_stubs.cc :11-:13 get REAL retirement at those rows,
  PER-LINK (18a corollary), via the E6 inverted mechanics + 3-face
  census discipline. NB: all THREE also carry `#include <daq.h>` (grep
  -l THIS pass) — the 18i graft/defer decision propagates.
- Then the link tail (wc ALL RE-RUN THIS pass: mpls 390 / vlan 236 /
  pppoe 243 / erspan2 145 / erspan3 147 / ciscometadata 235 /
  fabricpath 187 / trans_bridge 158 / ppp_encap 174; **cd_vlan.cc ALSO
  `#include <daq.h>`** — grep THIS pass), then the misc tail (llc 198 /
  vxlan 133 / user 167 / **icmp4_ip 345 / icmp6_ip 162** — the pair's
  two remaining extern tables, externs :55/:57 + ladder :113/:115 — and
  cd_default 83 LANDED 18c). misc trio faces THIS pass: llc/vxlan/user
  carry NO <daq.h> — the resident-half face measured at the small4
  copy tree: daq_common.h RESIDENT (the fmod graft rides) +
  packet_io/active.h RESIDENT (the 18g-era tun carry), but
  daqs/daq_user.h + packet_io/sfdaq.h + sfdaq_instance.h = 0 hits
  (user.cc's includes :24/:26/:28/:29) — re-measure at that row.
- The 39-extern census + the STATIC_CODEC_EXTERN_NAMES tripwire give
  every row its completeness checklist (ALL 18i/queue names ALREADY
  resident codec_api.rs :98-:128 — rows only ADD real TUs, NEVER touch
  codec_api.rs).

## Backlog (plan rows)
- 17z/18a/18b/18c/18d/18e/18f: DONE — wiki trios ALL LANDED (verified
  across passes; 18f = d13ccca, 18e = 1cacca1, earlier in prior rows'
  commits).
- 18g: **DONE (e6901f5)** — wiki trio **LANDED (313aab6)** verified THIS
  docs pass (greps PRESENT: Porting-status.md:97 status row + :105
  chapter note + Deviations-from-Snort-3.md:1742 deviations header;
  wiki stats at that commit: 103 commits / 399 files / 45,902 src lines
  / 541 tests — point-in-time faces, UNTOUCHED; the 18g-pass NEXT
  "18g trio OWED at d13ccca" line is SUPERSEDED by this measurement —
  the trio landed BETWEEN the two passes; wiki touched ZERO times by
  us, READ-ONLY rule held).
- 18h: **DONE (47654b3)** — codecs ip small four, THE ZERO-gate +
  cd_ah NAME-DRIFT row: `ip/cd_{esp,frag,pgm,auth}.cc` 227+190+211+172
  = **800 L** literal -> `src/codecs/{cd_esp,cd_frag,cd_pgm,cd_auth}.rs`
  292+269+213+228 = **1,002 L FLAT** + mod.rs wiring ONLY
  (framework/codec.rs + parse_conf.rs + codec_api.rs BYTE-UNTOUCHED;
  ladder cd_ah :98 / cd_esp :105 / cd_frag :108 / cd_pgm :121 resident,
  re-sed THIS pass; sids 272/294/454/456/458/459/465/466 resident
  codec_module.rs, ZERO new constants); `tools/small4_harness` NOW
  LINEAGE HEAD (exactly 6 tracked files, ZERO-gate face ENFORCED at
  build.sh :233; NO gate.txt added ANYWHERE — tracked gate face still
  ls-files-1 (gre); two-lineage census **UNDISTURBED MEASURED THIS
  pass: 25 gate.txt on disk / 9 x `4826fc22` holders / **17 distinct
  md5s** — direct md5sum|sort -u THIS pass, same face the row loop
  prints :442-:452); copy tree = gre 92 VERBATIM + 4 row cps + ZERO
  fresh cps, residency PROVEN by INVERTED E4 arms IN the build
  (checksum.h-only-pgm-dies :146-:150 / text_log.h-only-frag-dies
  :156-:159 / restored rc0 x4 :161-:166; pgm 2nd rider of checksum.h
  `b43628f3`, frag 1st rider of text_log.h `3e827113`; post-cp find 96
  asserted :125); NAME DRIFT: table cd_ah cc:166 + extern cd_ah
  codec_api.cc :40/:85 + ladder cd_ah, whole-src extern-cd_auth grep
  **0 THIS pass**, transcripts CARRY it (faceA :2/:4/:15 `LOAD auth` /
  `API ah ... name=auth` / `LOAD ipv6_frag`); Rust FILE base TRUE
  (cd_auth.rs) + table const mirrors the C TABLE (CD_AH/AH_API) +
  tripwire test pins names[0]=="cd_ah" !contains("cd_auth"); witness
  posture ZERO new (tunnel_bypass 0/0/0/0 measured :247; WIN trio
  inherited `ea1f79f3`/`4dd91018`/`f4afd35f` — 15th straight); vectors
  DEC 46 L `462f0ff6` + FACE-A 17 L `4755d48c` IMMUTABLE, FRESH x2 rc 0
  logs **byte-ident THIS pass**, O0==O2 BOTH faces; `tests/
  small4_parity_test.rs` 802 L 8 tests, 46/46 + 17/17 ORDERED replays,
  ZERO up_gate_* (honest zero-suite census cite); suite **549 passed /
  0 FAILED** THIS pass (66 result lines); clippy forced relint 0;
  .gitignore small4 block :420-:441 check-ignore re-verified THIS pass
  (stageables EXACTLY 6 harness files; status EMPTY after rebuilds);
  plan row + deviations VERIFY-GREPED (count 1 each: PORTING_PLAN.md:87
  / KNOWN DEVIATIONS.md:3015-:3186 = 172 L / 11 bullets — the
  message's ":3014 / 173 L" + the build.sh internal-cite staleness
  recorded honestly above, rows/sections NOT rewritten). **Wiki trio
  for 18h OWED** (next WIKI phase; `grep -rn 'row 18h|small four|
  cd_esp' /tmp/RustyPig.wiki` = 0 hits THIS pass; wiki HEAD 313aab6
  stops at 18g).
- 18: codecs — 18b-18h DONE; 18i = the DAQ trio (graft-vs-defer vs the
  hybrid daq_user.h face — MEASURED options table above, PLAN-0);
  queue continues per order above.
- 19: detection option engines (tree face re-stands from prior passes:
  52 .h+.cc files, 14,533 L; ~47 real Catch TEST_CASE faces — the GRE
  gate shape banked); 20: packet_io / DAQ (AF_PACKET via libc; the 17d
  RawData/daq_msg deferral + the daq_dlt.h graft close HERE — and note
  **18i may have ALREADY paid a minimal daq.h graft**, PLAN-0 face; the
  heavyweights + vlan all carry <daq.h> so the graft cost is banked
  across rows either way); 21: main CLI + `snort -q -c` end-to-end
  PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/small4_harness && bash build.sh` **x2** -> `SMALL4_HARNESS_OK
   vectors=46 faceA=17 gates=0` + vectors `462f0ff6` / FACE-A
   `4755d48c` md5 pins byte-ident across BOTH fresh runs (LOGS cmp
   byte-ident) + the E4-inverted residency arms + two-lineage census
   echo `9/25 holders 17 distinct`. `cd tools/gre_harness && bash
   build.sh` x2 for the GATE anchor (`GRE_HARNESS_OK vectors=26
   faceA=5 gate_lines=3`, gate `6751d1a8`, tail `1 assertion in 1 test
   case`). Rebuild `tools/fmod_harness` for the FROZEN-chain byte-ident
   echo (rc 0, gate `4826fc22` + tail VERBATIM `All tests passed (114
   assertions in 22 test cases)` + vectors `f0fdbab`) AND
   `tools/vocab_harness` (rc 0, `VOCAB_HARNESS_OK vectors=29`). Do NOT
   chase tun/eth/ext full-build rc 1 — they die at the by-design
   `-eq 24` drift face; verify their frozen face by direct md5s
   (tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`, eth
   `1bd98dbb`, witness census `9fad7e9d`/`be9bdd0b`/`f4afd35f`/
   `ea1f79f3`/`4dd91018`).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test`
   (zero FAILED; >= 549) + clippy 0 -> `.gitignore` block +
   `git check-ignore` -> commit+push -> plan row (grep-guard) ->
   deviations append (grep-guard; 18b-18h variant: verify-grep if
   shipped with the code commit) -> refresh THIS file -> commit+push
   docs -> wiki (status row + deviations + stats line — queue: 18h
   trio) -> push wiki.
