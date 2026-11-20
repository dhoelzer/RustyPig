# NEXT.md — takeover context & plan (2026-11-20, post-18c: codecs vocabulary + no-op codecs resident; donor = vocab_harness)

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

Current state (measured at this 18c verify-mode docs pass): plan rows
1–18c DONE. 95 commits counting the 18c code commit 9ed8a8f — **this
docs commit lands as the 96th**. **498 tests green / 0 FAILED** (full
`cargo test --all-targets` re-run AT THIS docs pass: summed
`test result` lines = 498 passed / 0 failed, `grep -c '^test result: ok'`
= 60 lines (59 at 18b + 1 from the cd_default in-crate tests); 498 = 487
+ 9 `tests/vocab_parity_test.rs` + 2 in-crate `src/codecs/cd_default.rs`
— the +9/+2 split re-counted THIS pass by `grep -c '#\[test\]'` on both
files), `cargo clippy --all-targets` **0 warnings** (forced relint THIS
pass: touched every .rs, `Checking snort3` ran, 0 warnings), 41,808
lines Rust across 129 `src/*.rs` files, 34 `tests/*_parity_test.rs`
whole-transcript replay tests among 59 tracked test files, 356 tracked
files (`git ls-files | wc -l`), 41 `tools/*_harness` dirs. GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `aa22a11` = **row 18b wiki trio LANDED**:
verified read-only at this docs pass — `git -C /tmp/RustyPig.wiki log -1`
prints `aa22a11 row 18b: status + deviations + stats (94 commits / 345
files / 40,993 src lines / 487 tests; FIRST codecs row, probe-only
zero-gate harness, gate 10th straight byte-ident
4826fc2233044a2d5429413faf0ae1af)` atop `9792858 row 18a`, and the 18b
trio greps PRESENT (`Porting-status.md:92/:95/:105` +
`Deviations-from-Snort-3.md:1077` — the 18b trio is NO LONGER debt; the
wiki is NEVER touched by code or plan rows). **The 18c wiki trio is
OWED** and is owed at the NEXT WIKI phase, not by this docs pass
(`grep -rn 'row 18c' --include='*.md' /tmp/RustyPig.wiki` = **0 hits**
verified this pass; the single bare `18c` hit at
`Deviations-from-Snort-3.md:1160` is the 18b-era flat-vs-dir deferral
note, not a status row). The owed trio = status row (codec_api.{h,cc} +
4 no-op cd_* TUs, 549 L ground -> 662 L Rust across 5 flat
src/codecs/*.rs + codec.rs/parse_conf.rs wiring, probe-only vocab
harness, gate untouched 11th straight, suite ZERO upstream, 498 tests) +
the row-18c deviations section (copy from KNOWN DEVIATIONS.md
:2322-:2418) + stats line ("96 commits / 356 tracked files / ~41,800 src
lines / 498 tests").

## 18c close-out — VERIFY MODE (plan row + deviations already landed WITH code commit 9ed8a8f; this pass greps-verify rather than append)
Like 18b, 18c's plan row and deviations section shipped inside the CODE
commit, so this docs pass is a verification pass. Everything below was
re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18c |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:82) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what 9ed8a8f shipped (verified
  against `git show --stat 9ed8a8f`: 17 files, harness + 5 Rust TUs +
  wiring + parity test + docs in one commit).
- **Deviations section**: `grep -c '^## codecs vocabulary (row 18c'
  KNOWN DEVIATIONS.md` = **1** at :2322, running to EOF at :2418 = 97
  lines / 14 bullets. **Verdict: adequate — leave, no follow-up edits.**
  Anchor re-grounding (every file opened THIS pass in ground snort3-src
  @ fe29cbe7403a): the 4 `static Codec* ctor` REAL at
  cd_default.cc:50 / cd_bad_proto.cc:61 / cd_no_next.cc:79 /
  cd_raw.cc:69 (cd_default.cc:50-:53 ctor+dtor body = the "cc:50-:54
  etc." anchor); BUILDING_SO alternation REAL at cd_bad_proto.cc:89-:93,
  cd_no_next.cc:107-:111, cd_raw.cc:97-:101; const_cast DROPPED anchor
  REAL at cd_no_next.cc:65 (`const_cast<uint32_t&>(raw.len) =
  ip::MIN_EXT_LEN;`); conf unguarded-deref anchor REAL at
  cd_no_next.cc:52 (`codec.conf->hit_ip6_maxopts(...)`);
  snort_config.h:278 `max_ip6_extensions = 0` + :450-:451
  `hit_ip6_maxopts` body REAL; PROTO_BIT__IP6_EXT 0x010000 REAL at
  decode_data.h:103; ip::MIN_EXT_LEN = 8 REAL at ipv6.h:32; the STATIC_
  CODECS ifdef arms REAL at codec_api.cc:39/:74 and :84/:119 with the
  call ladder cc:85-:118 (`load_plugins(cd_ah)` at :85); load-order pin
  cc:78-:82 = default/ipv4/ipv6/tcp/hopopts vs decl order cc:31-:36
  (hopopts at :34 BEFORE tcp at :36 — the SWAP the replay pins); extern
  census `grep -c '^extern const BaseApi\*' codec_api.cc` = **39** (= 5
  always-loaded + 34 STATIC_CODECS names); probe.cc:85 `api->dtor(c);`
  REAL; vectors:16 `EV 116 456` + vectors:29 `LOADS 5` + vectors:25-:28
  stub names REAL in the committed transcript; the 456 enum walk REAL
  (codec_module.h:203 `DECODE_IP_BAD_PROTO // = 450` -> :209
  `DECODE_IP6_EXCESS_EXT_HDR` = 456 via :204-:208); real cd_hopopts
  table def anchor REAL at ip/cd_hop_opts.cc:137 (matters for the 18e
  stub-retirement note in the scoping below).
- **Vectors stability**: `tools/vocab_harness/vectors.txt` 29 L md5
  `5da70e82416b6f769af8177d859331e7` — build.sh re-run FRESH THIS pass
  (rc 0): md5 stable, `O0==O2 vectors identity: BYTE-IDENT` self-check
  re-armed, residue self-check re-printed `row-TU app residue:
  cd_default=0 bad_proto=1 no_next=1 raw=0 codec_api=6 (=6, witnesses: 4
  arrays + load_plugins)`, E4 wall receipts on file
  (E4_cpputest_fatal/E4_plugin_manager/E4_snort_config.txt in the
  harness dir).
- **Gate chain LIVE**: fmod lineage donor rebuilt THIS pass (rc 0,
  `FMOD_HARNESS_OK vectors=61`): vectors `f0fdbab06fe1681af1c654531b917c55`
  + gate `4826fc2233044a2d5429413faf0ae1af` — the gate.txt tail reads
  verbatim `All tests passed (114 assertions in 22 test cases)` —
  **byte-ident = 11TH STRAIGHT confirmed by measurement, not
  assertion**. md5 census over all tracked gate.txt THIS pass: exactly
  **9 files** carry `4826fc22...` (fcap, fcshare, fconf, fcapi, finspect,
  fpolicy, fsvc, flog, fmod) out of 24 tracked gate.txt; the vocab
  build.sh re-counted the same 9 live (`gate census holders: 9 ...
  vocab gate.txt count 0`). 18c shipped NO gate.txt (probe-only row).
  The vocab_harness copy tree now also holds `daq_dlt.h` (the grafted
  `#define DLT_RAW 12` with the libpcap pcap/dlt.h:112-:114 cite in-
  file) — the graft is committed INSIDE the harness.
- **Test math**: 498 = 487 + 11 — `tests/vocab_parity_test.rs` 442 L,
  9 `#[test]` (`vocab_transcript_replay` 29/29 ordered + the 8 per-file
  arms) and `src/codecs/cd_default.rs` carries 2 in-crate `#[test]`;
  both counts re-measured THIS pass (9 + 2 = 11 = 60th-result-line
  delta). Suite result at THIS pass: all green, 0 FAILED.
- **commit census + gitignore**: 95 at HEAD 9ed8a8f (`git rev-list
  --count HEAD`); .gitignore vocab block at :308-:318+ re-verified by
  `git check-ignore` THIS pass (copy/ :309, probe :312, nm_U_* :318 all
  ignored; `vectors.txt` NOT ignored, rc 1 — stays tracked) — do NOT
  re-add.

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
   recipe) — cd_gre.cc (366 L) is EXACTLY that shape early (:34-:35)
   + trailing (:351-:366), the 18d->cd_gre row will run this recipe.
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
   re-censused EVERY build. The 18c row exercised it a second time:
   partial-.o row (4 real TUs + the REAL cp framework/codec.cc ride,
   build.sh :190/:258), zero gate material by per-file grep (0
   TEST_CASE / 0 TEST( / 0 UNIT_TEST across all six row files), zero
   gate artifacts shipped — `VOCAB_HARNESS_OK vectors=29` with the
   9-holder census echo. A fake Catch gate over a suite-zero row = the
   17p anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fmod_parity_test.rs` (1009 lines, whole 61-line replay + the
   retirement census), freshest-smallest `tests/vocab_parity_test.rs`
   (442 L, 29-line ordered transcript replay via Rc<RefCell> driver +
   sink closure mirroring the C witness printf interleave + 8 per-file
   arms, every value citing its vectors line — the pattern for
   zero-suite rows), then `tests/csum_parity_test.rs` (414 L, probe-
   only rows WITH a suite), `tests/flog_parity_test.rs`,
   `tests/fsvc_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 498; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings (force relint by touching all .rs),
   `vectors.txt` md5 stable across >= 2 clean rebuilds (gate.txt md5
   likewise — regenerable, hence .gitignore'd: md5-pinned in docs per
   row, NOT tracked), harness `.gitignore` block added (mirror
   siblings) and verified with `git check-ignore` BEFORE staging (the
   vocab block is .gitignore:308-:318+, landed inside code commit
   9ed8a8f). Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append) —
   the 18b/18c variant: BOTH may ship inside the code commit, then the
   docs pass VERIFY-greps them (count == 1 each) instead of inserting,
   and still re-measures every load-bearing claim. Refresh NEXT.md
   (FRESH rewrite), commit+push docs, update the wiki (status row +
   deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s/18b/18c do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH — `-lluajit` hits the .so and the gate probe dies at load, no rpath; `-lm -ldl` tail; nm pin fmod build.sh:961).
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum + vocab build: `cpputest_fatal.txt` wall receipt at checksum_test.cc:36 include; vocab E4_cpputest_fatal.txt re-printed at the 18c build). Upstream **CppUTest** suites (the 4 codecs/misc/test + ip/test suites, the 16g/16h lru suites — translated Rust-side) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + the snort_catch.h shim) runs natively.
- **daq_dlt.h exists NOWHERE** (ground find 0 at the 18c scoping pass; the graft now EXISTS as a committed fact: `tools/vocab_harness/copy/daq_dlt.h`, `#define DLT_RAW 12`, libpcap pcap/dlt.h:112-:114 cite in-file). Later rows that need DAQ dlt values cp/extend THAT graft, and row 20 cites the real DAQ include chain.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 var-first arms mirrored Rust-side).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction). Since 18a `file_trace` has its REAL def on BOTH sides (Rust token Cell armed via the transcribed cc:154 set_trace; harness side the row .o defines it, fcache_set_file_trace rides it, fmod stubs.cc:205).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/vocab_harness/` — **THE donor for row 18d+ (lineage head)**: the 18c probe-only-multi-TU pattern — 9 committed files (build.sh 325L, probe.cc 90L, witness_stubs.cc 14L, witness_conf.cc, PLAN.md 69L, vectors.txt 29L tracked, cp_audit_ok.txt), `copy/` tree = 44 headers incl. `codecs/codec_module.h`, `managers/{plugin_manager,plugin}.h`, `framework/{codec,base_api,api_options,decode_data,module}.h`, `main/{snort_config,snort_types}.h`, `protocols/{ip,ipv4,ipv6,layer,mpls,protocol_ids}.h`, `daq_dlt.h` GRAFT; build.sh :190/:258 cp+link braces ALREADY carry the REAL `framework/codec.cc` (231 L, the 17d base TU — the 18c PLAN-0 residue question CLOSED by real cp, `codec.o` present in copy/) + `protocols/ip.cc` + `sfip/sf_ip.cc` + `utils/util_cstring.cc`. Self-checks re-run THIS pass: O0==O2 identity, per-TU nm residue (`nm_U_*.txt`), 4-stub + load_plugins witness census, 9-holder gate census echo. vectors md5 `5da70e82416b6f769af8177d859331e7` (committed, NEVER edit); NO gate.txt (probe-only). **Its copy tree does NOT yet hold**: `protocols/eth.h`, `protocols/packet_manager.h`, `protocols/arp.h`, `trace/trace.h`, `log/log_text.h` (find run THIS pass — the fresh cps 18d needs; log_text.h rides the fmod text_log closure precedent).
- `tools/fmod_harness/` — the 18a donor & gate-lineage source (its cp braces + objs loop carry the FULL file_api closure); first third-party link (`libluajit.a` BY PATH + `-lm -ldl`, nm pin :961); §0.1 header-cp chain + 2 witness grafts (TraceOption in trace.h, DIOCTL in daq_common.h); stubs.cc 984L; build.sh 1164L; vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55`; gate md5 `4826fc2233044a2d5429413faf0ae1af` (rebuilt THIS docs pass, 11th straight). Its copy tree holds `framework/codec.h`, `config.h`, `main/snort_config.h`, `main/snort_types.h`, `daq_common.h` (graft), `protocols/protocol_ids.h`; NOT the codec-plugin headers (those landed in the vocab tree at 18c).
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
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base) — 18d/18e MUST re-read it: its RawData/daq_msg deferral closed partially at 18c (RawData dropped daq_msg, codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.**

## Next milestone — row 18d: the root/link layer + codec module (18c closed the vocabulary + no-op codecs; this scoping FRESH-measured at the 18c docs pass)

### 18d scale table — every `wc -l` re-run THIS pass, ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY

| unit (measured path THIS pass) | lines (`wc -l` this pass) | gate material (per-file grep THIS pass) |
|---|---|---|
| `root/cd_eth.cc` (path pin: **root/** — NOT codecs/ root/) | **262** | 0 TEST_CASE / 0 `TEST(` / 0 UNIT_TEST |
| `codec_module.h` | **269** | 0/0/0 |
| `codec_module.cc` | **71** | 0/0/0 |
| `link/cd_arp.cc` | **128** | 0/0/0 |
| **TOTAL** | **730** (262+269+71+128, summed this pass) | **NONE — probe-vectors-only row, second time (18c precedent)** |

The prior NEXT.md claim `codec_module.{h,cc} 340` **VERIFIED exactly**: 269 + 71 = 340 (measured per-file THIS pass — the pair-claim hid that the file is 269 header + only 71 body; the body is the trivial StaticCodecs params/`module_init` face, NOT the ~379-L monster an early draft feared). The 18e sum claim 721 re-verified (143+134+163+143+138 = 721 THIS pass) — still 9 L under 18d's 730; footnote stands (keep NEXT order).

### 18d shape facts (measured THIS pass — the surface the row must settle)
- **codec_module.h is the vocabulary header every later codec row includes**: the DECODE_* event enum home (`:203 // = 450` / `:209 EXCESS=456` — the anchors 18c's deviations already lean on) + the codecs-module parameter decls; includes ONLY `<cstdint>`, `framework/module.h` (RESIDENT in vocab copy tree — hit this pass) + `main/snort_types.h` (RESIDENT). Fresh header cp only, like 18c did — `codec_module.cc` (71 L) links as the row's own .o at 18d for the FIRST time (18c rule "do not link it" expired by design).
- **cd_eth.cc include closure vs the vocab copy tree (per-TU `grep '^#include'` THIS pass)**: `config.h` RESIDENT, `daq_dlt.h` RESIDENT (the 18c graft — cd_eth.cc:25 includes it, the graft's second consumer), `codecs/codec_module.h` RESIDENT (18c cp), `framework/codec.h` RESIDENT, `main/snort_config.h` RESIDENT; FRESH cps needed (find run THIS pass, all MISS in vocab tree): `log/log_text.h`, `protocols/eth.h`, `protocols/packet_manager.h`. packet_manager.h needs a header-ONLY ruling like 18a's §0.1 chain — if it drags inline definitions with unmet residue, nm-census BEFORE witnesses (17y/18a discipline); ground `managers/packet_manager.cc` = 1015 L and is NOT in any tree — do not link it.
- **codec_module.cc drags `trace/trace.h` (cc:26 — MISS in the vocab tree THIS pass)**: the fmod TraceOption graft precedent applies (fmod carried a grafted trace.h; the vocab tree never needed it). cp + graft arms as needed.
- **cd_arp.cc include closure**: `config.h` + `codecs/codec_module.h` + `framework/codec.h` + `protocols/arp.h` (MISS — fresh header cp; arp.h is a protocol struct header like the resident ipv4/ipv6 cps).
- **Residue question is PRE-resolved**: the vocab cp braces (build.sh :190/:258) ALREADY real-link `framework/codec.cc` + `protocols/ip.cc` + `sfip/sf_ip.cc` + `utils/util_cstring.cc` with witness census (4 cd_* stub tables + load_plugins body ONLY — the 18c build.sh residue echo, re-printed THIS pass: `codec_api=6 (=6, witnesses: 4 arrays + load_plugins)`). 18d lifts the vocab donor and re-runs the nm_U_*.txt per-TU census for cd_eth/codec_module/ccd_arp BEFORE writing witnesses.
- **The 4 witness-stub cd_*[] RETIREMENT SURFACE (analyzed THIS pass — the landmine map)**: `tools/vocab_harness/witness_stubs.cc:11-:14` defines `cd_ipv4[]/cd_ipv6[]/cd_tcp[]/cd_hopopts[]` stub tables (stub bodies :7-:10); the stub NAMES are FROZEN by vectors.txt:25-:28 (`LOAD cd_ipv4_stub`..`LOAD cd_hopopts_stub`) and consumed Rust-side by `src/codecs/codec_api.rs:82-:85` (deviations :2358-:2364: "a later row renaming a stub forks the vectors"). **18d DOES NOT retire any of them**: none of the four real tables is a 18d unit (ground path check THIS pass — real cd_hopopts table defers to ip/cd_hop_opts.cc:137 = 18e; cd_ipv4 790 L / cd_ipv6 733 L / cd_tcp 839 L land AFTER cd_gre/ICMP/udp in the order below). No name collision either: cd_arp[] is defined by cd_arp.cc itself at 18d and the vocab stub set carries NO cd_arp stub (witness_stubs.cc read in full THIS pass). **The retirement landmine surfaces at 18e** (cd_hop_opts): if 18e re-uses the vocab donor, per the 18a per-link corollary it must retire ONLY its OWN link's stub (witness_stubs.cc:10/:14 in its cp of the harness) with the retire-evidence echo, while frozen vocab keeps its stub + frozen vectors — and the 18e probe must decide whether its transcript still prints `LOAD cd_hopopts_stub` (frozen vocab face) vs the real hopopts face; the 18c Rust stub records ride the dormant-tripwire posture (deviations :2351-:2357 R3 rule: later rows never link a second table of the same name). Vectors fork = the vocab_parity 29/29 replay + codec_api.rs:82/:85 pins break — census-test both faces like fmod `trio_retirement_census`.
- Rust side: `src/codecs/` FLAT convention LANDED at 18c (5 TUs, C base names, per-file mod headers carry misc/ip/root provenance — deviations :2414-:2418); 18d adds `src/codecs/{cd_eth,codec_module,cd_arp}.rs` flat, order per C-alpha; NO dir refactor without a new deviations entry. `src/framework/codec.rs` already carries the 18c vocab block (BASE_API_VERSION 29 / CDAPI_VERSION 1900547 / CDAPI_SIZEOF 112 pin / codec_event PUB / protocol_id FINISHED_DECODE) — 18d wires eth/arp protocol ids + the codecs module parameters there or in codec_module.rs, not new subsystems.
- Gate material 0 across the whole 18d slab -> **probe-vectors-only, NO new gate.txt**; the 9-holder `4826fc22...` census (re-counted md5-census THIS pass = exactly 9 of 24 tracked gate.txt) must re-measure 9 at the 18d build too (frozen donor rule, vocab build.sh echo precedent) -> **12th straight byte-ident**.
- Vectors arms to drive (arm plan, values NEVER pre-typed — 17p lesson): cd_eth's DLT ladder (it answers DLT via the SAME graft constants — the graft's second consumer pins consistency), the ethertype dispatch table (prototypes already resident: protocol_ids.h cp + Layer/LayerId), the ARP decode ladder (arp.h structs), codec_module's parameter registration face + the DECODE_* event enum vs the 450/456 anchors already pinned, and `snort -h`-style codec help strings if the probe face reaches them (18c HELP `support for raw IP (DLT 12)` precedent — cd_eth's help arms are DLT-suffixed too, cd_eth.cc READ at the 18d recon).

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — both wc sweeps re-run THIS docs pass)
- **18e = the IPv6 extension chain**: cd_hop_opts 143 + cd_dst_opts 134 + cd_routing 163 + cd_mobility 143 + cd_igmp 138 = **721** (sum re-verified THIS pass) — every one rides the LANDED 17d CheckIPV6HopOptions / CheckIPv6ExtensionOrder + RFC order tables. **Carries the cd_hopopts witness-stub retirement decision (see 18d scoping above).**
- Then tunnels WITH self-include suite units — teredo 161+121 / gtp 291+140 / geneve 282+163 (self-include gate pattern = the 17f/17g precedent — but these 3 suites are **CppUTest**: Rust-side translation, deviation-noted, C gate untouched); `ip/checksum.h`'s 201-L suite is ALREADY translated (18b, 10 TEST/3 GROUP).
- Then **cd_gre 366 = the row that changes the gate (rule below)** — `ip/cd_gre.cc` wc re-run THIS pass = 366 ✓; then the ICMP pair (645+518), then udp 660 / ipv4 790 / ipv6 733 / tcp 839 (all wc re-run THIS pass — checksum.rs fully resident since 18b; the 4 stub tables get REAL retirement treatment at three of these rows, per-link), then the link tail (mpls 390/vlan 236/pppoe 243/erspan2 145/erspan3 147/ciscometadata 235/fabricpath 187/trans_bridge 158/ppp_encap 174), then the misc tail (llc 198 / vxlan 133 / user 167 / icmp4_ip 345 / icmp6_ip 162).
- The 18c STATIC_CODECS extern census (39 tables, cc-order) + the dormant STATIC_CODEC_EXTERN_NAMES tripwire give the later rows their completeness checklist: by the end of row 18 every extern must either link real or stay pinned dormant.

### The gate rule for the rest of row 18 (status at 18c close-out: **11 straight**, RE-MEASURED live THIS pass — fmod rebuilt fresh + md5 census, not asserted)
Gate md5 `4826fc2233044a2d5429413faf0ae1af` (tail line reads `All tests passed (114 assertions in 22 test cases)`, re-printed from the fresh fmod gate.txt THIS pass) has stayed **byte-ident every subrow through 18c** (chain holders md5-censused THIS pass = exactly 9 files: fcap, fcshare, fconf, fcapi, finspect, fpolicy, fsvc, flog, fmod, out of 24 tracked gate.txt; 18b AND 18c added NO gate = zero-gate rows, vocab build.sh echoed `gate census holders: 9` live at its build). Stays byte-ident 18d/18e.. until the **cd_gre subrow** (12th straight at 18d, 13th at 18e, ...). At the **cd_gre row the gate MUST change, exactly once**: ip/cd_gre.cc has BOTH shapes — an EARLY `#ifdef UNIT_TEST` include fragment at :34-:35 (`#include "catch/snort_catch.h"`) AND the trailing suite block at **:351-:366** — so the 17r rfind/balance-guard excision recipe runs on the PROBE build (LAST block only) while the gate build compiles the block verbatim via the fmod build.sh catch recipe (:249 catch.hpp pull, :270 shim heredoc, catch_main link), and the **duplicate-symbol rule** applies — the gate link carries the UT-compiled cd_gre TU ONLY, the plain probe `.o` excluded. Expected new gate line: **"All tests passed (115 assertions in 23 test cases)"** (= 114/22 + the `[cd_gre]` case "Validate error check for raw_len greater than GRE_HEADER_LEN" at :352 with its 1 CHECK — arithmetic from the measured 114/22 tail, but MEASURE the runner's line, NEVER type it from this forecast — the 17p lesson). That run's gate.txt becomes the NEW chain anchor md5; every later subrow byte-matches the NEW md5. CppUTest suites NEVER touch the C gate (no CppUTest on host — E4 receipt re-proven every csum AND vocab build). NEVER edit a frozen donor's gate/vectors to "fix" a count.

### 18d alternatives — honest comparison (measured THIS pass)
| option | size | gate material | verdict |
|---|---|---|---|
| **(a) NEXT order as scheduled: 18d = root/link (cd_eth 262 + codec_module 340 + cd_arp 128)** | 730 L, zero Catch material (0/0/0 per-file grep THIS pass) | still 0 | **CHOSEN**: codec_module.h is the DECODE_*/parameter vocabulary every 18e+ row includes (its :203/:209 anchors are already load-bearing in 18c's deviations); cd_eth is the root link layer every tunnel row decodes beneath; the 340 pair-claim verified exact, the body is 71 L trivial — the row is CHEAPER than its name suggests; witness-stub posture unchanged (no retirement at 18d, see above). |
| (b) swap 18d/18e (721 < 730, strict size order) | 721 L | still 0 | REJECT: saves 9 naive L but pulls the cd_hop_opts witness-stub retirement (the 18d scoping landmine) one row EARLIER with none of the 18d vocabulary landed; the existing NEXT footnote already rules keep-order. |
| (c) detour to `main/thread_config.cc` quick-win | 920 L wc re-verified THIS pass | **14** `[ThreadConfig]` Catch cases (grep re-counted THIS pass, body :615-:903 region) | The ONLY nearby row with fresh Catch gate material — first chance to extend the gated chain off the 114/22 anchor before cd_gre; needs hwloc witness ladder (17l numa precedent) + breaks codec-row continuity and the donor chain. Keep strictly as the fallback if row 18 stalls (18a ruling re-affirmed). |

## Backlog (plan rows)
- 17z: DONE (ef9bf83) — wiki trio LANDED (f91be60).
- 18a: DONE (74bcc23) — wiki trio LANDED (9792858).
- 18b: DONE (7e1744c) — wiki trio LANDED (aa22a11 — wiki HEAD verified THIS docs pass 18c: `row 18b` greps PRESENT at Porting-status.md:92/:95/:105 + Deviations-from-Snort-3.md:1077; wiki stats 94 commits / 345 files / 40,993 src lines / 487 tests).
- 18c: **DONE (9ed8a8f)** — codecs vocabulary landed: `codec_api.{h,cc}` + 4 no-op cd_* TUs (549 L ground -> **662 L Rust** across src/codecs/{codec_api 174L, cd_default 130L, cd_bad_proto 97L, cd_no_next 139L, cd_raw 122L}.rs, all FLAT, +102 framework/codec.rs vocab block +14 parse_conf.rs max_ip6_extensions); `tools/vocab_probe-only harness NOW LINEAGE HEAD (9 committed files, 44-header copy tree incl. daq_dlt.h GRAFT, REAL framework/codec.cc cp, witness census 4 stubs + load_plugins); vectors 29L md5 `5da70e82...` stable (fresh rebuild THIS pass, O0==O2 arm); gate chain 11th straight CONFIRMED live THIS pass (fmod rebuild byte-ident + 9-holder md5 census); `tests/vocab_parity_test.rs` 442L 9 tests (29/29 ordered replay + 8 per-file arms) + 2 in-crate cd_default tests; suite re-run **498/0** THIS pass (60 result lines); clippy forced relint 0 THIS pass; .gitignore vocab block :308-:318+ check-ignore re-verified THIS pass; plan row + deviations VERIFY-GREPED this pass (count 1 each: PORTING_PLAN.md:82 / KNOWN DEVIATIONS.md:2322-:2418, 97L/14 bullets, verdict ADEQUATE-LEAVE with every anchor re-grounded — see 18c close-out). **Wiki trio for 18c OWED** (next WIKI phase; wiki HEAD aa22a11 stops at 18b; `row 18c` grep = 0 hits verified THIS pass).
- 18: codecs — 18b/18c DONE; 18d scoping ABOVE (730 L claim VERIFIED with per-file wc table THIS pass; `codec_module.{h,cc}` 340 sub-claim verified exactly); row continues 18e/.. per order above.
- 19: detection option engines (~30k+ subset claim stands but the tree measures **14,533** .h+.cc with **~47** embedded Catch TEST_CASEs — fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc 5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1, ips_context_data.cc 1 — real Catch material to carry like 17f/17r; re-grep at that row's scoping pass); 20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg deferral + the 18c daq_dlt.h graft both close HERE — graft is now a committed fact at vocab copy/daq_dlt.h); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/vocab_harness && bash build.sh` -> vectors md5 stable x2 clean rebuilds (NO gate — probe-only); rebuild `tools/fmod_harness` too for the gate-chain byte-ident echo.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard; 18b/18c variant: verify-grep if shipped with the code commit) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
