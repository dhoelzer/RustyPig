# NEXT.md — takeover context & plan (2026-11-20, post-18g: cd_gre gate-change row landed; donor = gre_harness)

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

Current state (measured at this 18g verify-mode docs pass): plan rows
1–18g DONE. **103 commits at HEAD e6901f5** (`git rev-list --count
HEAD` THIS pass; the 18g commit's own "103rd commit" line checks out —
this docs commit lands as the **104th**). **541 tests green / 0 FAILED**
(full `cargo test` re-run AT THIS docs pass: summed `test result` lines
= 541 passed / 0 failed over 65 result lines; 541 = 530 at 18f + 11
`tests/gre_parity_test.rs` (`grep -c '#\[test\]'` = 11 re-measured THIS
pass — note the `--all-targets` variant sums the SAME 541 over 64
lines; cite one face per pass, both agree); `src/codecs/cd_gre.rs` 668 L
carries ZERO in-crate `#[test]` (grep 0 re-run THIS pass), `cargo
clippy --all-targets` **0 warnings** (forced relint THIS pass: touched
every .rs, `Finished` line present, `grep -c '^warning'` = 0), 45,902
lines Rust across 141 `src/*.rs` files (`find src -name '*.rs' -exec
wc -l {} +` THIS pass), 38 `tests/*_parity_test.rs` whole-transcript
replay tests, 399 tracked files (`git ls-files | wc -l`), 45
`tools/*_harness` dirs. GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `d13ccca` = **row 18f wiki trio LANDED**:
verified read-only at this docs pass — `git -C /tmp/RustyPig.wiki log
-1` prints `d13ccca row 18f: status + deviations + stats (101 commits /
389 files / 45,233 src lines / 530 tests ...)` atop `1cacca1 row 18e`,
and the 18f trio greps PRESENT (`Porting-status.md:96` status row +
`:103` chapter note + `Deviations-from-Snort-3.md:1573` deviations
header — the EARLIER NEXT edition's "wiki stops at 18e / 1cacca1, the
18f trio OWED" line is SUPERSEDED by this measurement: the trio LANDED
as measured; this docs pass touched the wiki ZERO times). **The 18g
wiki trio is OWED** and is owed at the NEXT WIKI phase, not by this
docs pass (`grep -rn 'row 18g' --include='*.md' /tmp/RustyPig.wiki` =
**0 hits** verified THIS pass). The owed trio = status row
(ip/cd_gre.cc, 366 L ground -> 668 L Rust + 723 L replay test; THE
gate-change row: TRACKED gate.txt md5 `6751d1a8...`, runner tail 'All
tests passed (1 assertion in 1 test case)', two-lineage census 9
holders / 25 gate.txt / 17 distinct md5s, suite 541) + the row-18g
deviations section (copy from KNOWN DEVIATIONS.md :2901-:3013) + stats
line ("104 commits / 399 tracked files / 45,902 src lines / 541 tests"
— LIVE values at the docs commit, re-measure at the wiki pass before
typing).

## 18g close-out — VERIFY MODE (plan row + deviations shipped WITH code commit e6901f5; this pass greps-verify + re-ground rather than append)
Like 18b-18f, 18g's plan row and deviations section shipped inside the
CODE commit, so this docs pass is a verification pass. Everything below
was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18g |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:86) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what e6901f5 shipped (`git show
  --stat e6901f5`: 14 files, +2,202 — harness 8 tracked files + docs
  row + deviations + cd_gre.rs + mod.rs wiring +
  tests/gre_parity_test.rs 723 L in one commit).
- **Deviations section**: `grep -c '^## codecs ip cd_gre (row 18g'` =
  **1** at :2901, running to EOF at :3013 = 113 lines / **9** bullets
  (`grep '^- \*\*'` count THIS pass). **Verdict:
  ADEQUATE-READ-LEAVE** — the gate-change disclosure (shim route, E7
  orphan-`#endif` cut-to-EOF face, E9 dup face, UB SEQ-arm bounded
  substitution, assert no-twin, ZERO-new-witness, ROW-SCOPED VOCAB) all
  re-grounded. **TWO honest count drifts recorded this pass** (land
  rule: rows/sections/messages NEVER rewritten, no force-push): (1)
  the e6901f5 message copy "stageables EXACTLY the 7 harness files + 5
  src/tests" — live faces: harness stageables are **8** tracked files
  (`git ls-files tools/gre_harness` = PLAN.md build.sh catch_main.cc
  gate.txt probe.cc probe_dec.cc vectors.txt vectors_faceA.txt) and
  the non-harness staged paths are **3** (cd_gre.rs, mod.rs,
  gre_parity_test.rs); the TOTAL "EXACTLY 14 staged paths" matches the
  --stat face exactly. (2) Deviations :2951 "the copy tree 86+1+2 = 89
  find-counted" — live face: `find tools/gre_harness/copy -type f !
  -name '*.o'` = **92** (= tun donor 86 + gate shim `catch/catch.hpp`
  + `catch/snort_catch.h` + probe-side `cd_gre_probe.cc` + row
  `cd_gre.cc` + 2 fresh cps gre.h/checksum.h; the copy tree is
  .gitignore'd so it never enters the stageable face). Both are
  count-coverage drifts of the scoping arithmetic, NOT behavioral
  claims — every behavioral claim below re-verified independent of
  them.
- **Harness FRESH x2 THIS pass, rc 0 both runs**: `GRE_HARNESS_OK
  vectors=26 faceA=5 gate_lines=3` tail verbatim; anchors live-asserted
  by build.sh :43-:49 EVERY build (`grep -c '#ifdef UNIT_TEST'` == 2;
  sed :34 `#ifdef UNIT_TEST` / :35 `#include "catch/snort_catch.h"` /
  :351 reopen / :352 the ONE TEST_CASE / whole-file `CHECK` grep == 1
  (inside the block, line :364) / :366 `#endif`); ground cd_gre.cc wc
  366 re-run THIS pass; table arms :337-:341 re-sed — REAL
  `BUILDING_SO`/`SO_PUBLIC`/`#else const BaseApi* cd_gre[] =` at
  **:340**. md5 pins ALL re-summed byte-exact THIS pass: vectors.txt 26
  L `41bd7d1bdac01694eeda1f3e56869e77`, vectors_faceA.txt 5 L
  `783649440def7ec3b032970d223a8a6a`, gate.txt 3 L
  `6751d1a8c21da0fdfed87ddfd4d37c5f` (TRACKED — the FIRST tracked
  gate.txt in the lineage; build.sh :378-:382 pins md5+wc+the RUNNER's
  own wording `1 assertion in 1 test case`), probe.cc 22 L
  `66cfb942...`, probe_dec.cc 93 L `e01eb950...`, catch_main.cc 2 L
  `a4d3d600...` (heredoc-regenerated, CATCH_CONFIG_MAIN grep-assert 1
  at :143), catch/catch.hpp `74ef54e848cf843c99e3acdb94ce2b1a`
  byte-ident to the rules_harness vendored face, shim
  copy/catch/snort_catch.h `177e1852...` (passthrough `#pragma once +
  #include "catch/catch.hpp"` — TEST_CASE macro NEVER remapped, the
  ground block compiles verbatim; the TestCaseInstaller route stays
  REJECTED, deviation cited at :2928-:2939). Receipts
  `/opt/data/cache/scratch/row18gdocs/{gre,fmod,vocab}_rebuild_18gdocs*.log`.
- **TWO-LINEAGE CENSUS — LIVE FACE MOVED INSIDE gre build.sh (rules
  forward)**: THIS pass measured 25 `tools/*/gate.txt` on disk,
  **9** of md5 `4826fc22...` (fcap/fcapi/fconf/fcshare/finspect/flog/
  fmod/fpolicy/fsvc — all byte-frozen) + **17 distinct md5s** total
  (the 9 holder face + gre's `6751d1a8` + 15 other-own-md5 gates);
  gre build.sh :401-:404 asserts `-eq 9` and `-eq 25` and writes the
  17-face receipt `gate_md5_lineages.txt` — the census loop MEASURES,
  never a typed forecast (17p). **Drift face RE-MEASURED THIS pass**:
  the frozen tun/eth/ext build.sh point-in-time `ls gate.txt -eq 24`
  asserts now FAIL (tun :334, eth :598, ext :320 — rebuild rc 1 at
  `test 25 -eq 24`; the `-eq 9` holder half passes, all 9 byte-frozen).
  This is the deviation recorded AT the row (:2921-:2927): frozen donor
  rows are historical artifacts, NEVER rewritten/force-pushed; do NOT
  "fix" their build.sh. Their frozen face is instead verified by
  direct md5 re-sums: tun vectors `2a792479` + faceA `81602890`, ext
  `da218429`/`0fa79b53`, eth `1bd98dbb`, all ZERO drift THIS pass —
  and each build dies only AFTER its per-row asserts pass (vectors md5
  pins at tun :203-:204 / ext :141 / eth :339 run live before the
  census line even fails).
- **Gate chain FROZEN side — MEASURED not asserted**: fmod rebuilt
  FRESH THIS pass rc 0 (`FMOD_HARNESS_OK vectors=61`): gate
  `4826fc2233044a2d5429413faf0ae1af` + gate.txt tail VERBATIM re-grepped
  `All tests passed (114 assertions in 22 test cases)` (count 1) +
  vectors `f0fdbab06fe1681af1c654531b917c55`; vocab donor FRESH rc 0
  (`VOCAB_HARNESS_OK vectors=29`, vectors `5da70e82...` stable — the
  cd_gre anchors moved from tun/ext echo asserts to the gre harness
  owning them). 5-fingerprint frozen census all re-md5'd BYTE-EXACT
  THIS pass: vocab witness_stubs.cc `9fad7e9d...` (4 cd_ipv4/ipv6/tcp/
  hopopts stub tables :11-:14 intact; cd_gre/cd_udp/cd_icmp4/cd_icmp6/
  esp/frag/pgm/auth stub grep **0/0** across vocab witness_stubs +
  codec stubs re-run THIS pass — landmine ZERO for the whole 18h
  queue) / codec stubs.cc `be9bdd0b...` / eth stubs_18d.cc `f4afd35f`
  (gre build.sh carries the E6 arm) / tun witness_18f.cc `ea1f79f3...`
  (CARRIED by gre — the ONLY witness, `tunnel_bypass_enabled`; TUNNEL_
  GRE 0x40 rides the SAME table, snort_config.h:125) / tun
  witness_conf.cc `4dd91018...` re-md5'd at the gre tree face.
- **Rust-side anchors re-grounded THIS pass**: `src/codecs/cd_gre.rs`
  668 L + `tests/gre_parity_test.rs` 723 L / 11 `#[test]` (26/26
  ORDERED DEC replay + 5/5 ORDERED FACE-A + `gre_gate_contract` pins
  the tracked runner tail Rust-side + `up_gate_gre_*` — the FIRST
  codec row whose Rust twin mirrors a gate that ACTUALLY RAN); sids
  DECODE_GRE_* 160-165 confirmed resident at codec_module.rs:107-:112
  (sed THIS pass — the row adds ZERO new constants); ladder names ALL
  resident in codec_api.rs STATIC_CODEC_EXTERN_NAMES (sed THIS pass:
  cd_ah :98, cd_esp :105, cd_frag :108, **cd_gre :110**, cd_icmp4
  :112, cd_icmp4_ip :113, cd_icmp6 :114, cd_icmp6_ip :115, cd_pgm
  :121, cd_udp :128 — tripwire pins cc order cd_geneve < cd_gre <
  cd_gtp; NEVER re-touch, the row pattern); framework/codec.rs +
  parse_conf.rs + codec_api.rs BYTE-UNTOUCHED. THE 18b two-way parity
  pin re-read at vectors:25-:26 (`ENC ok -> 1 cksum-bytes 103 255`,
  `UPD chksum-bytes 127 255`) — the FIRST C-consumer cross-check of
  Rust `checksum::cksum_add`, both pairs byte-exact.
- **Test math**: 541 = 530 + 11; plain `cargo test` 65 result lines,
  FAILED/panicked grep 0, at THIS pass; 38 parity files (37 + gre).
- **commit census + gitignore**: 103 at HEAD e6901f5; .gitignore gre
  block at :392-:419 re-verified by `git check-ignore` THIS pass (copy/
  :394, o2/, probe binaries, gate binaries, `gate*/E4*/E8*/E9*/nm_U_*/
  *_O0/O2 receipts, gate_md5_lineages.txt, witness_conf.cc, cp_audit_
  ok.txt, *.log all ignored rc 0; vectors.txt + vectors_faceA.txt +
  gate.txt + build.sh + PLAN.md + probe.cc + probe_dec.cc +
  catch_main.cc NOT ignored, rc 1 — stageables exactly 8, do NOT
  re-add). `git status --short` EMPTY after the docs-pass rebuilds —
  artifacts fully absorbed.
- **Scoping-claim correction (the method proving itself)**: the 18f-
  pass NEXT line "**cd_auth has NO codec_api extern at all**" was HALF
  WRONG — re-measured THIS pass: no extern is NAMED `cd_auth` anywhere
  in ground (grep whole src: zero hits outside its own TU) BUT
  cd_auth.cc's real table is `const BaseApi* cd_ah[] =` at
  ip/cd_auth.cc:166 (the SAME BUILDING_SO/#else arms :163-:167 as
  gre :337-:341) and the extern `extern const BaseApi* cd_ah[];`
  rides codec_api.cc:**40** + load_plugins(cd_ah) at :85 — a TRUE-
  NAME DRIFT face (file base `cd_auth` vs table `cd_ah`), the
  cd_hop_opts drift family reappearing, ladder name `cd_ah` ALREADY
  resident codec_api.rs:98. Lesson: file-based greps miss name-drift
  tables — at the cd_auth row grep by TABLE name, and the tripwire
  test must pin the file-vs-extern name pair (the 18e cd_hop_opts
  tripwire precedent).

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
   recipe — the FRESHEST working shape is NOW AT GRE ITSELF:
   `tools/gre_harness/build.sh` :132 catch.hpp cp + :139 catch_main.cc
   heredoc + :143 CATCH_CONFIG_MAIN pin, plus fmod :249/:270 and fctx
   :60-:63/:403-:407 for the older carries; TestCaseInstaller route
   REJECTED at 18g, deviation :2928-:2939). Run it; record cases/
   assertions in `gate.txt`; at 18g+ an embedded-Catch codec row's
   gate.txt is TRACKED with pinned md5 + wc + the runner's own tail
   wording (the gre pattern). NEVER gate on grep-estimated assertion
   counts — pin case names/counts from grep, measure assertions from
   the runner (17p: grep said 36, the runner said 42). When gate and
   probe link the same TU, use the **duplicate-symbol rule**: every
   UT-compiled TU's plain `.o` is EXCLUDED from the gate link — at gre
   this is QUANTIFIED (nm defined census {cd_gre} x1 per .o,
   intersection 1; E9 flipped-assert: plain+UT co-link MUST die at
   'multiple definition of `cd_gre''). When a TU has BOTH early
   `#ifdef UNIT_TEST` fragments AND a trailing suite block, excise the
   LAST block only, via `rfind` + **cut-to-EOF** + brace-balance guard
   + head-count assert (17r file_lib + the gre E7 face: cutting to the
   block's `}` leaves orphan `#endif without #if` — cut-to-EOF
   MANDATORY). The 17y INVERSION lesson (witness-block retirement at
   real-TU landing; fsvc :706-:707/:778/:827), the 18a PER-LINK
   corollary (retirement applies to the CURRENT donor's stubs ONLY;
   frozen donors keep blocks + vectors/gate byte-frozen; census test
   pins both faces) and the 18b PROBE-ONLY corollary (ZERO .o to
   every donor link + unbuildable suite dialect -> probe-only harness,
   nm-proved zero contribution, chain re-censused every build) all
   stand. 18b-18f exercised probe-only five times; 18g BANKED the
   gate-change detour: from this row on there are TWO gate md5
   lineages (frozen 9/4826fc22 + gre's own), and the point-in-time
   holder counts baked into FROZEN donors' build.sh scripts FAIL BY
   DESIGN on later rows — census loops belong in the NEWEST harness,
   frozen rows are never rewritten (deviation :2921-:2927). The 18d
   INVERTED-DUP face (new real cp retires an OLD frozen donor stub —
   E6 MUST-fail `multiple definition .* snort_str`, receipt re-printed
   every build, own stubs_18d.cc `RETIRED at 18d:` marker :30) and the
   18e FACE-RULE (flip rehearsals = BUILD RECEIPTS only, never pins)
   carry unchanged. A fake Catch gate over a suite-zero row = the 17p
   anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`. The 18g UB ruling
   reinforces: a C out-of-window write (the SEQ-arm, cc:149/cc:151)
   gets a DEFINED bounded substitution with the zero-contribution
   measured on the vectors arm + an IN-window unit face — never
   replicate the overrun.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/gre_parity_test.rs` (723 L, 26L DEC + 5L FACE-A ORDERED
   replays + `gre_gate_contract` runner-tail pin + `up_gate_gre_*`
   statement-for-statement mirror of a gate that ACTUALLY RAN — the
   pattern for gate rows), then `tests/tun_parity_test.rs` (860 L, 9
   tests, DUAL-face + translations for multi-face zero-suite rows),
   `tests/eth_parity_test.rs` (608 L), `tests/vocab_parity_test.rs`
   (442 L), `tests/csum_parity_test.rs` (414 L),
   `tests/flog_parity_test.rs`, `tests/fsvc_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 541; never
   trust a summed total from a run containing FAILED; cite one
   plain-vs-all-targets face per pass), clippy --all-targets ZERO
   warnings (force relint by touching all .rs), `vectors.txt` md5
   stable across >= 2 clean rebuilds (gre's FRESH x2 both byte-ident
   THIS pass; gate.txt md5 likewise — legacy rows' gate.txt stay
   .gitignore'd md5-pinned in docs, the GRE gate.txt is the tracked
   exception, md5-pinned in build.sh), harness `.gitignore` block
   added (mirror siblings) and verified with `git check-ignore` BEFORE
   staging (the gre block is .gitignore:392-:419, landed inside code
   commit e6901f5). Then commit + push, insert the plan row (grep-
   guard: count must be 0 before insert — the numa double-append
   incident cost a force-push), append deviations (one grep-guarded
   append) — the 18b-18g variant: BOTH ship inside the code commit,
   then the docs pass VERIFY-greps them (count == 1 each) instead of
   inserting, and still re-measures every load-bearing claim. Refresh
   NEXT.md (FRESH rewrite), commit+push docs, update the wiki (status
   row + deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s/18b-18g do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH — `-lluajit` hits the .so and the gate probe dies at load, no rpath; `-lm -ldl` tail; nm pin fmod build.sh:961). 18d-18h-queue row TUs carry ZERO lua refs (grep -ci lua asserted every build; re-assert at gre too via the carried tree).
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum + vocab + eth + ext + tun build: E4_cpputest_fatal `CppUTest/CommandLineTestRunner.h: No such file` flipped-assert EVERY build, plus the checksum_test.cc:36 precedent). Upstream **CppUTest** suites (misc/test/{teredo,gtp,geneve}_codec_test.cc — landed-and-translated at 18f as `up_tun_*` — plus the STILL-LIVE 16g/16h lru ones) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + shim) runs natively — banked at 18g: the cd_gre gate ran REAL. **ip/checksum.h is NOW DONOR-RESIDENT** (gre cp, `b43628f3` ground face; the 18b row was Rust-inline; cd_pgm's same-dir `#include "checksum.h"` (cc:28) rides it — no fresh cp needed).
- **`#include <daq.h>` does NOT exist in ground** (find THIS pass: only `daqs/daq_user.h` + `src/pub_sub/daq_message_event.h` — never confuse them): the udp/icmp4/icmp6 trio's `#include <daq.h>` at cc:25 each is the EXTERNAL DAQ header, row-20 pressure; the fmod `daq_common.h` + vocab `daq_dlt.h` graft precedents are the only stand-in pattern. esp/frag/pgm/auth carry NO daq.h include (measured THIS pass) — the small four are DAQ-FREE.
- **daq_dlt.h graft IS a committed fact**: `tools/vocab_harness/copy/daq_dlt.h` + the eth/gre copy carry `DLT_RAW 12` / `DLT_EN10MB 1` / `DLT_PPP_ETHER 51` (libpcap master cites). Later rows cp/extend THAT graft; row 20 cites the real DAQ include chain.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 var-first arms + 18d-18g replay mirrored Rust-side — gre carries the gre build.sh :311-:312 pins: `bool [a-z][a-z0-9]*=.*->decode` count -ge 8 AND `printf.*->decode` count == 0 on probe_dec.cc, asserted every build; Rust side stores every bool before field reads).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY. Since 18a `file_trace` has its REAL def on BOTH sides.
- Frozen-donor build.sh rc-1 face (the 18g drift codified above): when a docs pass rebuilds tun/eth/ext and sees rc 1 at an `-eq 24` gate.txt ls-assert, that is the BY-DESIGN drift face (25 files since gre's gate) — NEVER edit frozen scripts; verify their frozen face by direct vectors md5 re-sums instead.

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/gre_harness/` — **THE donor for row 18h+ (lineage head)**: the 18g gate-change pattern — exactly **8** tracked files (build.sh 412L md5 `de698f473815cd83a84f7b0cff57a19b`, probe.cc 22L md5 `66cfb942...`, probe_dec.cc 93L md5 `e01eb950...`, PLAN.md 104L md5 `efaa88e134d4bbdae9f1b2c3d9eb651b`, catch_main.cc 2L md5 `a4d3d600...` heredoc-regenerated, **gate.txt 3L md5 `6751d1a8...` TRACKED** — the runner tail is the new chain anchor, vectors.txt 26L md5 `41bd7d1b...` tracked, vectors_faceA.txt 5L md5 `783649440d...` tracked; NO witness file — the carried `witness_18f.cc` `ea1f79f3` resolves the single `tunnel_bypass_enabled` U-line); `copy/` tree = the tun donor VERBATIM + shim pair (catch/catch.hpp `74ef54e8` + gate-side snort_catch.h passthrough `177e1852`) + probe-side excised `cd_gre_probe.cc` + row `cd_gre.cc` + EXACTLY 2 fresh header cps (protocols/gre.h 50 L `7b07af8e` + codecs/ip/checksum.h 284 L `b43628f3` — first donor entry of the 18b lib; E4 walls flipped x2, post-cp rc 0; utils/endian.h MEASURED NOT in closure, E13) = 86+6 = 92 sources find-counted `! -name '*.o'` (the row's 89 face recorded as drift; copy/ is .gitignore'd); witness_conf.cc heredoc byte-ident `4dd91018`. Self-checks re-run THIS pass at BOTH fresh rebuilds (rc 0 `GRE_HARNESS_OK vectors=26 faceA=5 gate_lines=3`): gate md5 + wc + tail-wording pins :378-:382; O0==O2 cmp arms THREE streams (DEC + FACE-A + GATE); E9 flipped-assert x1 build; E4 flipped x2; anchors :43-:49; sids census x4 (:62-:67); event-site sed pins :69-:72; two-lineage census loop :401-:404 (9/25/17). FRESH x2 reproducibility = the md5 pins survive a clean re-clone rebuild — the harness is the contract.
- `tools/tun_harness/` — the 18f donor (superseded at 18g as head; kept for lineage; its `-eq 24` census line rc-1 fails by design NOW — see drift face): exactly 7 tracked files, DUAL-face vectors 40L `2a792479...` + 7L `81602890...` both re-md5'd ZERO drift THIS pass (direct md5s, not the build), witness_18f.cc `ea1f79f3` THE witness everyone since 18f carries, nm U-census arms 10/24/42. NO tracked gate.
- `tools/ext_harness/` — the 18e donor (kept): 7 tracked files, DUAL faces 27L `da218429...` + 9L `0fa79b53...` re-md5'd zero drift THIS pass; cd_gre echo asserts :50-:53 (the pre-18g anchor face, historical — gre now owns those anchors). `-eq 24` face dead by design. NO tracked gate.
- `tools/eth_harness/` — the 18d donor (kept): exactly 5 tracked files (build.sh 608L, probe.cc 41L, PLAN.md 83L, stubs_18d.cc 35L `RETIRED at 18d` marker md5 `f4afd35f...` — carried by every later row, vectors.txt 15L `1bd98dbb...` re-md5'd zero drift), the EXTENDED `daq_dlt.h` graft, EOFLOW/EOFTRH/EOFDAQ heredoc carries, thread_config.h hwloc excision carry, lua-seam assert (:60-:62). NO tracked gate.
- `tools/vocab_harness/` — the 18c donor (kept; rebuilt FRESH THIS pass rc 0 `VOCAB_HARNESS_OK vectors=29`): 9 committed files, witness_stubs.cc 14L `9fad7e9d...` — **the 4 cd_*[] stub tables (cd_ipv4/cd_ipv6/cd_tcp/cd_hopopts) at :11-:14 frozen by vectors:25-:28; cd_gre/cd_udp/cd_icmp4/cd_icmp6/esp/frag/pgm/auth stub counts 0 — re-grepped THIS pass**, vectors.txt 29L `5da70e82...` stable; the `daq_dlt.h` GRAFT originated here.
- `tools/fmod_harness/` — the 18a donor & **FROZEN gate-lineage source** (rebuilt fresh at every docs pass for the byte-ident echo — done THIS pass, frozen 9-holder chain intact): cp braces + objs loop carry the FULL file_api closure; first third-party link (`libluajit.a` BY PATH, nm pin :961); stubs.cc 984L; build.sh 1164L; vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55`; gate md5 `4826fc2233044a2d5429413faf0ae1af` + tail VERBATIM re-grepped THIS pass `All tests passed (114 assertions in 22 test cases)`; catch-recipe carry :249/:270 (fctx :60-:63/:403-:407 the older full shape — the grep-gate clone target was gre, and 18h+ cite GRE's own :132/:139 now).
- `tools/csum_harness/` — row 18b, **the probe-only pattern for ZERO-.o rows**: no gate shipped; build.sh self-checks = ground-header md5 pin (:37), E4 CppUTest wall receipt (:67-:70), dialect proof (:72-:73), nm ZERO-text-symbols proof (:79-:80), O0==O2 (:116), 9-holder census (:154). vectors 16L md5 `e4baf7816440e18917d3249597f60b88`. `ip/checksum.h` NOW enters donor trees via gre's cp — the udp/icmp/pgm rows inherit residency; the 18b face stays Rust-side.
- `tools/flog_harness/` — the 17z donor: vectors 50L md5 `b260ec6a...`.
- `tools/fsvc_harness/` — the 17y donor: the landmine inversion (23 collisions); vectors 64L md5 `54864705...`.
- `tools/fpolicy_harness/` — the 17x donor: vectors 27L md5 `b989a8d5...`.
- `tools/finspect_harness/` — the 17w donor: vectors 103L md5 `3cbd009e...`.
- `tools/fcapi_harness/` — the 17v donor: vectors 21L md5 `a953a501...`. NB dir name `fcapi_harness` (pinned, do not "fix").
- `tools/fconf_harness/` — the 17u donor: vectors 20L md5 `65968e1c...`.
- `tools/fcshare_harness/` — the 17t donor: vectors 25L md5 `03d43c14...`.
- `tools/fcap_harness/` — the 17s donor: vectors 27L md5 `0208a691...`; gate md5 `4826fc22...` — the 114/22 frozen chain STARTS here.
- `tools/fctx_harness/` — FileContext + capture/mempool/segment closure donor: vectors 610L md5 `839b5566...`; gate md5 `42349372...` (its OWN 18/91 link, distinct lineage md5, never joined the 4826fc22 chain). `PLAN.md` = the RECON→HARNESS→PORT contract example; :60-:63/:403-:407/:413 = the older CATCH SHIM + catch_main + gate-link-line shape (the 17r dup-symbol precedent lives in this tree; gre carries the quantified E9 face).
- `tools/fflows_harness/` — flowz graft donor: vectors 146L md5 `bd8c00af...` (DO NOT touch); gate md5 `e14626fc...`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: vectors 278L md5 `b69db310...` (DO NOT touch); gate md5 `6b3c041e...`.
- `tools/filib_harness/` — file_api header closure + interposed SnortClock fake clock. vectors 273L md5 `77ffd8e4...` (DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE.
- `tools/fstats_harness/` — carries the ONLY file_api test/ suite (upstream `file_api/test/file_stats_test.cc` via the catch shim).
- `tools/textlog_harness/` — row 16r: time() interposition precedent.
- `tools/rules_harness/` — SnortConfig EOFCFG shim; hosts `copy/catch/catch.hpp` `74ef54e8...` — byte-ident at gre THIS pass (the vendored Catch every shimmed gate pulls).
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base; its stubs.cc md5 `be9bdd0b437d1f6c56c841e8155d9e70` re-md5'd THIS pass is the FROZEN donor the E6-YES arms re-collide against every build; grep cd_gre/udp/icmp/esp/frag/pgm/auth counts 0 — no landmine) — the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.**

## Next milestone — row 18h: the ip queue FRESH-measured at the 18g docs pass (udp heavyweight + ICMP pair; the small four scoped with the cd_ah name-drift correction)

### The queue face, measured THIS pass (ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY)
- **Gate material: ZERO everywhere**: combined grep
  `TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST` over `ip/cd_udp.cc`,
  `cd_icmp4.cc`, `cd_icmp6.cc`, `cd_esp.cc`, `cd_frag.cc`, `cd_pgm.cc`,
  `cd_auth.cc` = **0/0/0/0/0/0/0** (loop re-run THIS pass) — honest
  probe-only rows per the 18b-18f corollary; NO frozen-donor census
  numbers to break; the 25/9/17 two-lineage face stands untouched.
- **UDP heavyweight** `ip/cd_udp.cc` **660 L** (wc THIS pass; path pin
  holds — ip/ NOT misc/): table `const BaseApi* cd_udp[] =` at
  **:655**; externs codec_api.cc **cd_udp :70**, load_plugins :115;
  ladder `cd_udp` resident codec_api.rs:128. Includes (grep THIS pass
  cc:22-:36): the resident base (config.h, codecs/codec_module.h,
  framework/codec.h, log/messages.h, log/text_log.h,
  main/snort_config.h, utils/util.h, **checksum.h — now DONOR-RESIDENT
  since gre**) + `#include <daq.h>` at **:25** (EXTERNAL, not in
  ground — find THIS pass: zero daq.h; ONLY daqs/daq_user.h +
  pub_sub/daq_message_event.h) + `protocols/teredo.h` :32 (**RESIDENT**
  — b7adb3d8 carried since 18f) + `protocols/udp.h` :33 (ground **68
  L**, find vs gre copy tree = 0 hits -> **fresh cp**).
- **ICMP pair** `ip/cd_icmp4.cc` **645 L** (table cd_icmp4[] :640,
  externs **cd_icmp4 :54 + cd_icmp4_ip :55**, load :99-:100) and
  `ip/cd_icmp6.cc` **518 L** (table cd_icmp6[] :513, externs **cd_icmp6
  :56 + cd_icmp6_ip :57**, load :101-:102); ladder `cd_icmp4/4_ip/6/
  6_ip` ALL resident codec_api.rs:112-:115. BOTH carry
  `#include <daq.h>` :25 + `checksum.h` (same-dir, resident) :33/
  :35; icmp4 includes `protocols/icmp4.h` :31 (ground **259 L**, 0 hits
  in gre copy -> **fresh cp**); icmp6 includes `protocols/icmp6.h` :31
  (ground **196 L**, 0 hits -> **fresh cp**) AND `protocols/icmp4.h`
  :32 (cross-rider — one fresh cp feeds both rows). The four extern
  names (icmp4/icmp4_ip/icmp6/icmp6_ip) = the pair's completeness
  bar; there is NO cd_icmp4_ip/cd_icmp6_ip FILE in ip/ — those tables
  live in `misc/cd_icmp4_ip.cc` 345 L + `misc/cd_icmp6_ip.cc` 162 L
  (misc tail), the row-18 extern census ties the pair together.
- **The small four** (wc THIS pass): `ip/cd_esp.cc` **227 L** (table
  cd_esp[] :221, extern **cd_esp :47** load :92, ladder cd_esp
  codec_api.rs:105 — includes ONLY the four resident headers, NO
  protocol header, NO daq.h -> **zero-fresh-cp candidate**);
  `ip/cd_frag.cc` **190 L** (table cd_frag[] :184, extern **cd_frag
  :50** load :95, ladder :108 — adds log/text_log.h, resident ->
  **zero-fresh-cp candidate**); `ip/cd_pgm.cc` **211 L** (table
  cd_pgm[] :206, extern **cd_pgm :63** load :108, ladder :121 — adds
  same-dir `checksum.h` :28 = RESIDENT since gre's first-ever cp ->
  **zero-fresh-cp candidate, first row to RIDE the checksum residency
  it paid for**); `ip/cd_auth.cc` **172 L** — **THE NAME-DRIFT ROW**:
  table `const BaseApi* cd_ah[] =` at **:166** (BUILDING_SO arms
  :163-:167, gre-family), extern `cd_ah` codec_api.cc **:40** load
  :85, ladder `cd_ah` codec_api.rs:98 — there is NO extern named
  `cd_auth` anywhere in ground (grep THIS pass); the 18f-pass NEXT
  "auth has NO extern" line corrected above; includes ONLY the four
  resident headers -> **zero-fresh-cp candidate**; the row's tripwire
  MUST pin file-base-vs-table-name drift (cd_hop_opts 18e face
  precedent).
- **Bypass seam**: cd_udp/cd_icmp* decode paths ride the same
  tunnel_bypass seam (TUNNEL_GRE face homed at gre; masks TUNNEL_*
  snort_config.h:119-:128 sed-pinned since 18f; witness_18f carried).
  Landmine posture **ZERO for every 18h name** (cd_udp/cd_icmp*/
  cd_esp/cd_frag/cd_pgm/cd_ah stub grep 0/0 THIS pass in vocab
  witness_stubs + codec stubs, both donors).
- **STATIC_CODECS extern census**: 39 `extern const BaseApi* cd_[]`
  lines re-counted THIS pass (cc face); by end of row 18 every extern
  links real or stays pinned dormant. ip-region hit-list: cd_ah :40,
  cd_esp :47, cd_frag :50, cd_gre :52 (**LANDED 18g**), cd_icmp4 :54,
  cd_icmp4_ip :55, cd_icmp6 :56, cd_icmp6_ip :57, cd_pgm :63, cd_udp
  :70 + the ipv4/ipv6/tcp trio.

### 18h alternatives — honest comparison (measured THIS pass)
| option | size | fresh-cp / risk face | verdict |
|---|---|---|---|
| **(a) plan order: 18h = udp + icmp4 + icmp6 (the DAQ trio)** | 660+645+518 = 1,823 L | fresh cps: udp.h 68 + icmp4.h 259 + icmp6.h 196 (teredo.h + checksum.h RESIDENT); the FIRST `#include <daq.h>` (cc:25 x3) — external header NOT in ground (find THIS pass); two PLAN-0 options, NEVER pre-decided: minimal `daq.h` graft w/ fmod daq_common.h + vocab daq_dlt.h precedent, or the row-20 deferral posture (grep-assert the wall like the E4 faces); 2 probe rows likely (pair + udp) | **HIGHEST plan fidelity**; the DAQ head-on moment arrives with the 3 heavyweight rows anyway — bank it once. |
| **(b) small four first: esp + frag + pgm + auth** | 227+190+211+172 = 800 L | ZERO fresh cps (ALL four closures measured resident THIS pass — the cheapest tree delta in the lineage); DAQ-FREE; the cd_ah name-drift row early w/ tripwire; pgm rides the checksum residency 18g paid | Honest tail-order options — PLAN-0 at 18h calls (a) vs (b); the 18f "no pre-ordering" face stands; if (b) lands first, 18i-18k absorb the DAQ trio unchanged. |
| (c) detour `src/main/thread_config.cc` | 920 L | 14 `[ThreadConfig]` Catch TEST_CASEs (18f-pass count; re-grep at that row if ever); needs the hwloc witness ladder (17l; eth excision carry); breaks codec continuity + donor chain | Fallback ONLY if row 18 stalls (18a/18c/18d/18f ruling — re-affirmed, still the only nearby fresh-gate option OUTSIDE codecs). |

### Rules forward from 18g (the gate-change carried into 18h+)
- The two-lineage census (9 x 4826fc22 frozen + gre's own) is the
  LIVE face — run its loop INSIDE the newest harness (build.sh carries
  the -eq pair), NEVER re-pin 24/9/17 arithmetic into a new row's
  docs without measuring THAT pass (17p: every typed count before its
  row is a dead forecast).
- 18h rows are ZERO-gate material (combined grep 0 x7 THIS pass) ->
  probe-only harnesses clone the TUN pattern (lineage 18f) on the GRE
  copy tree (now incl. checksum.h + gre.h + the catch pair — trim
  unused cp faces at PLAN 0, NEVER pre-type the count).
- A codec row that ever DOES ship a suite (thread_config fallback, or
  row-19 detection material) clones the GRE gate shape: shim passthrough
  + catch_main heredoc + TRACKED gate.txt md5/wc/tail-wording pin +
  rfind/cut-to-EOF excision + E9 dup flipped-assert.
- TRUE-NAME DRIFT (the cd_ah face): every landing row greps the TABLE
  name (`const BaseApi\* \w+\[\]` sed) not just file base; the ladder
  tripwire test pins file-vs-extern pairs; table sites: udp :655 /
  icmp4 :640 / icmp6 :513 / esp :221 / frag :184 / pgm :206 /
  auth(cd_ah) :166 — sed THIS pass.

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — both find+wc sweeps re-run THIS docs pass, zero drift)
- After the queue above: the 3 heavyweight stub-table owners ipv4 **790**
  / ipv6 **733** / tcp **839** (18f-pass wc, re-verify at their rows);
  cd_ipv4/cd_ipv6/cd_tcp witness_stubs.cc :11-:13 get REAL retirement
  at those rows, PER-LINK (18a corollary), via the E6 inverted
  mechanics + 3-face census discipline.
- Then the link tail (18f-pass wc, re-measure at that pass: mpls 390 /
  vlan 236 / pppoe 243 / erspan2 145 / erspan3 147 / ciscometadata
  235 / fabricpath 187 / trans_bridge 158 / ppp_encap 174), then the
  misc tail (llc 198 / vxlan 133 / user 167 / **icmp4_ip 345 /
  icmp6_ip 162** — the pair's two remaining extern tables, :55/:57 +
  :113/:115 ladder — and cd_default 83 LANDED 18c).
- The 39-extern census + the STATIC_CODEC_EXTERN_NAMES tripwire give
  every row its completeness checklist (ladder faces sed-cited in the
  18h scoping above; ALL queue names already resident — rows only
  ADD real TUs, NEVER touch codec_api.rs).

## Backlog (plan rows)
- 17z: DONE (ef9bf83) — wiki trio LANDED (f91be60).
- 18a: DONE (74bcc23) — wiki trio LANDED (9792858).
- 18b: DONE (7e1744c) — wiki trio LANDED (aa22a11).
- 18c: DONE (9ed8a8f) — wiki trio LANDED (72d39cd).
- 18d: DONE (5c8e31e) — wiki trio LANDED (63a6170).
- 18e: DONE (c30a30e) — wiki trio LANDED (1cacca1).
- 18f: DONE (3ece5c6) — wiki trio **LANDED (d13ccca)** verified THIS
  docs pass (greps PRESENT: Porting-status.md:96 status row + :103
  chapter note + Deviations-from-Snort-3.md:1573 deviations header;
  wiki stats at that commit: 101 commits / 389 files / 45,233 src
  lines / 530 tests).
- 18g: **DONE (e6901f5)** — codecs ip cd_gre, THE gate-change row:
  `ip/cd_gre.cc` 366 L literal -> `src/codecs/cd_gre.rs` 668 L FLAT +
  mod.rs wiring ONLY (framework/codec.rs + parse_conf.rs +
  codec_api.rs BYTE-UNTOUCHED; ladder name resident codec_api.rs:110;
  sids 160-165 resident codec_module.rs:107-:112); `tools/gre_harness`
  NOW LINEAGE HEAD (exactly 8 tracked files; **FIRST REAL CODEC CATCH
  GATE**: ground embedded block runs VERBATIM under the shim route,
  gate.txt TRACKED md5 `6751d1a8...` wc 3, RUNNER tail `All tests
  passed (1 assertion in 1 test case)` pinned at build.sh :378-:382,
  NEVER typed); **TWO-LINEAGE CHAIN**: sanctioned break after 14
  straight — frozen 9 x `4826fc22` stay byte-frozen, gre adds ONE
  own-md5 gate; census loop gre build.sh :401-:404 MEASURED 9/25/17
  THIS pass; tun/eth/ext -eq 24 ls-asserts drift-fail BY DESIGN
  (deviation :2921-:2927; holders -eq 9 PASS; frozen vectors re-md5'd
  zero drift direct THIS pass; rows NEVER rewritten); probe side =
  rfind + cut-to-EOF + brace-balance (E7 face MANDATORY) + E9 dup
  flipped-assert EVERY build + E4 header-wall x2 + ZERO new witness
  (witness_18f carried, `ea1f79f3`); fresh cps = gre.h 50 L `7b07af8e`
  + checksum.h 284 L `b43628f3` (first-ever donor entry of the 18b
  lib), endian MEASURED not in closure (the '~3' forecast face died —
  2 measured); vectors DEC 26 L `41bd7d1b...` + FACE-A 5 L
  `783649440d...` IMMUTABLE, THREE O0==O2 streams (DEC+FACE-A+GATE)
  byte-ident at the FRESH x2 rebuilds rc 0; the UPD/ENC vectors lines
  `103 255`/`127 255` = FIRST C-consumer cross-check of Rust
  checksum::cksum_add, byte-exact (two-way parity pin); UB SEQ-arm
  bounded substitution, zero-contribution measured; `tests/
  gre_parity_test.rs` 723 L 11 tests = 26/26 + 5/5 ORDERED replays +
  `gre_gate_contract` runner-tail pin + `up_gate_gre_*` — FIRST codec
  row mirroring a gate that ACTUALLY RAN; suite **541 passed / 0
  FAILED** THIS pass (65 result lines plain; 64 lines --all-targets,
  same sum); clippy forced relint 0; .gitignore gre block :392-:419
  check-ignore re-verified (stageables exactly 8 — the "7 harness
  files + 5 src/tests" breakdown drift in the e6901f5 message
  recorded honestly, total-14 face stands, NO rewrite); plan row +
  deviations VERIFY-GREPED (count 1 each: PORTING_PLAN.md:86 /
  KNOWN DEVIATIONS.md:2901-:3013, 113 L / 9 bullets, verdict
  ADEQUATE-READ-LEAVE with every anchor re-grounded — copy-tree 89-vs-
  92 find-count drift recorded, rows NOT rewritten). **Wiki trio for
  18g OWED** (next WIKI phase; wiki HEAD d13ccca stops at 18f; `grep
  -rn 'row 18g' --include='*.md' /tmp/RustyPig.wiki` = 0 hits verified
  THIS pass).
- 18: codecs — 18b/18c/18d/18e/18f/18g DONE; 18h = the ip queue
  (udp/icmp DAQ trio vs small four, PLAN-0 options MEASURED above);
  queue continues per order above.
- 19: detection option engines (tree face RE-MEASURED THIS pass: **52**
  .h+.cc files, **14,533** L total — matches the prior claim; the ~47
  embedded Catch TEST_CASE face stands from the 18f-pass grep —
  fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc
  5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2,
  sfrim.cc 1, ips_context_data.cc 1 — real Catch material carried with
  the GRE gate shape now banked; re-grep at that row's scoping pass);
  20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg
  deferral + the daq_dlt.h graft close HERE — and note the 18h pair
  may have ALREADY paid a minimal `daq.h` graft decision, PLAN-0
  face, see options table); 21: main CLI + `snort -q -c` end-to-end
  PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/gre_harness && bash build.sh` **x2** -> `GRE_HARNESS_OK
   vectors=26 faceA=5 gate_lines=3` + vectors `41bd7d1b` / FACE-A
   `783649440d` / gate `6751d1a8` md5 pins ALL byte-ident across BOTH
   fresh runs (E4/E9 flipped-assert arms + two-lineage census echo
   `frozen 9/25 holders 17 distinct md5s`). Rebuild `tools/fmod_harness`
   for the FROZEN-chain byte-ident echo (rc 0, gate `4826fc22` + tail
   VERBATIM `All tests passed (114 assertions in 22 test cases)` +
   vectors `f0fdbab`) AND `tools/vocab_harness` (rc 0, `VOCAB_HARNESS_OK
   vectors=29`, 9-holder echo). Do NOT chase tun/eth/ext full-build rc
   1 — they die at the by-design `-eq 24` drift face (holder -eq 9
   half passes); verify their frozen face by direct md5s instead
   (tun `2a792479`/`81602890`, ext `da218429`/`0fa79b53`, eth
   `1bd98dbb`, witness census `9fad7e9d`/`be9bdd0b`/`f4afd35f`/
   `ea1f79f3`/`4dd91018`).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test`
   (zero FAILED; >= 541) + clippy 0 -> `.gitignore` block +
   `git check-ignore` -> commit+push -> plan row (grep-guard) ->
   deviations append (grep-guard; 18b-18g variant: verify-grep if
   shipped with the code commit) -> refresh THIS file -> commit+push
   docs -> wiki (status row + deviations + stats line) -> push wiki.
