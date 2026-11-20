# tun_harness PLAN — row 18f: tunnel trio (misc/cd_teredo + cd_gtp + cd_geneve, 734 L, probe-only)

Seeded in-repo from scratch recon `cache/scratch/row18f/` READ-ONLY port recon @ ground snort3-src `fe29cbe7403acc0dd428065a69d8f29cc311c18e` (untouched all pass; re-measured at seed). Port repo HEAD `2c3033b` (18e docs close-out; lineage head = **ext_harness** per donor census; gate chain 13 straight -> 18f = 14th). Every number below re-measured THIS pass (fresh `wc -l < /opt/data/snort3-src/src/codecs/misc/test/*_test.cc` + md5s; scratch E4/E4b/nm receipts byte-agree). Donor = `tools/ext_harness/copy/` carried VERBATIM (cp -a). Ground READ-ONLY.

## 0. VERDICT: single row, 734 L three misc/ tunnel TUs, zero suites in-row (own wc/grep re-measured at seed)

| claim | measured | verdict |
|---|---|---|
| misc/cd_teredo.cc 161 | md5 `649dde0666ee14a9514cd02744815dd5` | ✓ |
| misc/cd_gtp.cc 291 | md5 `d0719e95a9ddc985ae09c4ba853bf17a` | ✓ |
| misc/cd_geneve.cc 282 | md5 `0d05bf86e27d8c9c0fac63edfb5bc7ed` | ✓ |
| TOTAL 734 | 161+291+282 = **734** (sum asserted in build.sh; NEXT "Trio 734L" agrees) | ✓ |
| TRUE NAMES | file base == extern name on ALL THREE: `cd_teredo` cc:159(ternary face):152-:160, `cd_gtp`, `cd_geneve` — NO cd_hop_opts/cd_hopopts tripwire this row | ✓ |
| gate material 0/0/0 | grep TEST_CASE/TEST_GROUP/^TEST(/UNIT_TEST = 0 per row file | ✓ |
| suites live in misc/test AND self-include the TUs | teredo 121 / gtp 140 / geneve 163 L; `#include "../cd_*.cc"` at teredo :29 / gtp :29 / geneve :20 (build.sh greps own; NEXT's ":20/:29/:29" = geneve-first enumerate order, same measured fact); TEST_GROUP 1/1/1, ^TEST( 2/2/3, CHECK-family 3/8/19 (teredo,gtp,geneve order; old NEXT "3/3/4" = GROUP+TEST conflation, SUPERSEDED) | ✓ |
| misc/ ships ZERO headers | `find src/codecs/misc -name '*.h'` = 0 (NEXT cite re-verified) | ✓ |
| row-vs-subrow call (NEXT deferred to PLAN 0) | **SINGLE row** 734 L: shared witness (one), shared fresh-cp delta (two headers), one table family — same one-commit scale as 18d 730 / 18e 721 | ✓ |

## 1. Naming judgment — `tun_harness` PINNED

`grep -rn 'tun_harness'` NEXT.md + PORTING_PLAN.md + all tools/*/PLAN.md = 0 pre-hits (measured): pre-unnamed like ext. Pin = `tools/tun_harness/` ("tunnel trio"; one-word lineage semantics csum/vocab/eth/ext; NEVER `misc_harness` — misc/ also holds llc/vxlan/user/icmp*_ip tail rows).

## 2. Copy tree = ext donor face VERBATIM + EXACTLY 3 row cps + EXACTLY 2 fresh header cps

Fresh-cp census vs ext face (NEXT 18f scoping row RE-CONFIRMED at seed): `protocols/teredo.h` 44 L md5 `b7adb3d85e5f7dccccbf427ff119f6f5` **MISS->cp**, `packet_io/active.h` 240 L md5 `ce6085794642721562df16740895a08a` **MISS->cp**, `protocols/geneve.h` **RESIDENT byte-ident** `10cfe860d4dab013aca85b7cdbdde9a2` (eth-era cp; cmp -s vs ground asserted). Copy tree = 81 + 3 row + 2 header = **86 source files** (find -type f ! -name '*.o' assert). Donor integrity spot-pins: codec_module.h `3f3bd927…` + snort_config.h `638120b5…` + `test ! -e copy/codecs/codec_api.{h,cc}`.

## 3. E4 WALL FACES — flipped-assert EVERY build (the 18f headline shape)

Pre-cp face (row cps staged, NO fresh headers): compile each row TU vs the ext donor face —
- cd_teredo **MUST fail** `fatal error: protocols/teredo.h` (cc:27) -> `E4_cd_teredo.txt` (grounding grep first line matches scratch receipt)
- cd_geneve **MUST fail** `fatal error: packet_io/active.h` (cc:28) -> `E4_cd_geneve.txt`
- cd_gtp **MUST pass rc=0 empty** -> `E4_cd_gtp.txt` (gtp needs NO fresh cp — include closure fully resident)
Post-cp face (2 header cps in): all three **MUST pass rc=0 empty** -> `E4b_cd_*.txt` (2 fresh cps CLOSE all .o, scratch E4b face reproduced).
CppUTest box-dead: all three ground misc/test suites (compiled -I copy-post-cp) MUST die at `CppUTest/CommandLineTestRunner.h: No such file` -> `E4_cpputest_fatal.txt` (no catch conversion, no mock face — geneve suite adds MockSupport as the lone rider; NEVER replayed as a gate, 18b CppUTest precedent).

## 4. Witness posture — EXACTLY ONE new witness: `SnortConfig::tunnel_bypass_enabled`

U-dumped by **all three** TUs (scratch nm re-verified all 3 receipts): `snort::SnortConfig::tunnel_bypass_enabled(unsigned short) const`. Ground def `main/snort_config.cc:1020-:1023`: `return !((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(proto));`. Home = **`witness_18f.cc`** (TRACKED, hand-authored — the ext donor witness_conf.cc face stays byte-frozen md5 `4dd91018…` and carries no tunnel member): body = ground-shaped `!((mask & proto) or daq)` over a witness OBSERVABLE TABLE `tun_mask` (SFDAQ unlinked -> daq arm pinned false); DEC probe toggles the table across the **3 masks**: TUNNEL_GTP `0x01`, TUNNEL_TEREDO `0x02`, TUNNEL_GENEVE `0x200` (enum TunnelFlags snort_config.h:117-:128; call sites cd_teredo.cc:106, cd_gtp.cc:177, cd_geneve.cc:166 — sed-verified seeds; masks chosen = ground defaults bypass-true face + each bit's bypass-false arm).

## 5. Landmine posture — ZERO (three names UNstubbed everywhere; asserted)

`grep 'cd_geneve\|cd_gtp\|cd_teredo'` in vocab witness_stubs.cc + codec_harness stubs.cc + vocab/codec/ext link faces = **0** (frozen vocab D-table census stays 4 = ipv4/ipv6/tcp/hopopts; ext retired stays 3). No stubs_18f.cc. codec_api.cc stay face: STATIC_CODECS extern census 39 holds (tunnel six at codec_api.cc:51/:96, :53/:98, :68/:113 — sed assert x2 pairs); the probe link pulls NO codec_api object (nm guard: zero `load_codecs` in probe .o's, ext face-A rule inherited). FACE-II rehearsal NOT needed (nothing freezes against these names — flip only FORKS frozen faces; 18e codified rule).

## 6. Probe faces (both TRACKED; values measured, NEVER typed)

- **FACE-A** `probe.cc`: 3-table walk via in-probe load_plugins witness -> `vectors_faceA.txt`: LOAD geneve/gtp/teredo + `LOADS 3` + API geneve size/ver carry + mod_ctor arms geneve=1 gtp=1 **teredo=0** (ground cd_teredo table has null mod_ctor — the honest asymmetry arm, vs igmp=1 at 18e).
- **DEC** `probe_dec.cc`: R6 var-before-printf (build.sh greps `bool *=.*->decode` >=5, `printf.*->decode` ==0); arms (measured at first run, pinned md5+wc): TER short1->0 / auth-shord->0 / mask00 -> 1 bypass=**1** (ground tunnel_mask=0 face) + mask02 -> bypass=**0** / mask02 lyr=8 next=IPV6 bits=128; GTP short7->0 / type1->0 / v0-shord EV 298 + 0 / v1-ok mask01 bypass=0 lyr=8 bits=256 / v1-twice EV 297 / v1-badlen EV 298; GEN short7 EV 180 / ver1 EV 181 / C-flag EV 183 / mask0200 -> 1 bypass=0 lyr=8 bits=2097152 next=ETHERNET arm + mask0000 bypass=1; PID arms TER 257 / GTP 258 / GEN 265 (protocol_ids.h:128/:129/:136 literals); RuleMap walk faces GEN rules=5 sid0=180 (codec_module.h:108-:112) + GTP rules=2 sid0=297 (h:151/:152; Rust enum greps codec_module.rs :157 pin the already-landed values — NEVER re-walked); TER mod_ctor=0 arm.
- Link (both faces): donor REAL-cp .o's (codec/ip/sf_ip/util_cstring/util/module **plus text_log.o** — geneve.cc:26 U `TextLog_Print`, donor-resolved, ZERO witness) + 3 row .o + probe .o + ext witness_conf.o + eth stubs_18d.o (queue_event EV-printer inherited) + **witness_18f.o**. O0==O2 byte-ident both faces (cmp asserted); hygiene zero `0x` in tracked faces.
- Per-TU U-census receipts `nm_U_cd_{teredo,gtp,geneve}.txt`: MEASURED at first run (scratch pre-receipts: teredo 10 / gtp 24 / geneve 42 sort-unique), all three carry the ONE tunnel_bypass U-line + app-family arms (geneve TextLog_Print + Module family + basic_string; gtp _Unwind/typeinfo family; teredo minimal = memcpy/ntohs/new pair) — all resolved by donor T defs (codec.o codec_event; module.o Module family; text_log.o TextLog_Print), ZERO witnesses beyond witness_18f.

## 7. Rust posture (names ALREADY resident in the ladder — zero rename landmine)

Future TUs `src/codecs/cd_teredo.rs / cd_gtp.rs / cd_geneve.rs` (flat convention; TRUE names, no tripwire). `codec_api.rs` STATIC_CODEC_EXTERN_NAMES ALREADY names `cd_geneve` :109 / `cd_gtp` :111 / `cd_teredo` :126 (grep asserted) — records land per row TU, consts NEVER touched. Tunnel mask = the first SnortConfig field in this chain with NO Rust twin yet: `tunnel_mask` (snort_config.h:393 NSDMI 0) rides the config row ruling (18c max_ip6_extensions precedent); queue for KNOWN DEVIATIONS at the Rust row (17v style).

## 8. Gate identity — 14th straight; ZERO gate artifacts in this harness

build.sh asserts: md5 census exactly **9** holders of `4826fc2233044a2d5429413faf0ae1af` among exactly **24** tracked tools/*/gate.txt; `find $H -maxdepth 1 -name 'gate*'` == 0; fmod oracle-recipe greps re-read from COMMITTED fmod build.sh. 14th-straight rides the SESSION fresh **fmod+vocab rebuilds** (14th straight pair; logs scratch row18f/{fmod,vocab}_rebuild_18f.log — fmod tail `All tests passed (114 assertions in 22 test cases)`, vocab `VOCAB_HARNESS_OK vectors=29`), NEVER typed here (17p). cd_gre anchors re-measured (ip/cd_gre.cc :34/:35 `#ifdef UNIT_TEST`/catch include, TEST_CASE :352, 366 L) — 18f pre-digs NOTHING, cd_gre stays QUEUED sanctioned chain change, 18f changes NO gate.

## 9. Frozen-donor re-md5 (FIVE donor diff-0 pins) + stageables (EXACTLY 7) — check-ignore verified

Re-md5 every build (diff-0 vs pins): vocab `witness_stubs.cc` `9fad7e9d…` · vocab `vectors.txt` `5da70e82…` · codec_harness `stubs.cc` `be9bdd0b…` · eth `stubs_18d.cc` `f4afd35f…` · ext `witness_conf.cc` `4dd91018…` (+ ext `probe.cc af4c83fc`/`probe_dec.cc 35d7f771`/`vectors da218429`/`vectors_faceA 0fa79b53` = ext row face itself undisturbed — grep-counted).
Tracked: `PLAN.md` · `build.sh` · `probe.cc` · `probe_dec.cc` · `witness_18f.cc` (the ONE new witness home, md5-pinned) · `vectors_faceA.txt` · `vectors.txt`.
Ignored: copy/ · o2/ · probe* binaries · all *.o · witness_conf.cc (heredoc-regenerated byte-ident to ext pin) · vectors_{O0,O2}+faceA twins · nm_U_*.txt · E4*/E6*.txt · cp_audit_ok.txt · gate* · *.log.
