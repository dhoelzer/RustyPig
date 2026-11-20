# gre_harness PLAN — row 18g: ip/cd_gre.cc (366 L), THE gate-change row (first real codec Catch gate)

Seeded in-repo from scratch recon `cache/scratch/row18g/` READ-ONLY port recon @ ground snort3-src `fe29cbe7403a` (untouched; re-measured at seed). Port repo HEAD `39f36d1` (18f docs close-out; lineage head = **tun_harness** per donor census; gate chain 14 straight → 18g = the sanctioned break). Every number below re-measured THIS pass (fresh sed/wc/md5 on the ground file + a FULL scratch compile-rehearsal at the tun donor face — receipts `cache/scratch/row18g/{E1..E13,gate_*,nm_*,probe_walk_out}.txt` byte-agree). Donor = `tools/tun_harness/copy/` carried VERBATIM (cp -a, 86 sources). Ground READ-ONLY.

## 0. VERDICT: single row, 366 L one ip/ TU, gate material = 1 REAL Catch TEST_CASE (all anchors re-run THIS pass)

| claim | measured | verdict |
|---|---|---|
| `ip/cd_gre.cc` 366 L | wc = 366 (also live-asserted by ext build.sh :50-:53 + tun build.sh :72-:75 at the 18f pass) | ✓ |
| DUAL `#ifdef UNIT_TEST` face | `grep -c '#ifdef UNIT_TEST'` = **2**: early include-only fragment **:34/:35/:36** (`#ifdef UNIT_TEST` / `#include "catch/snort_catch.h"` / `#endif`) + TRAILING suite block **:351 → :366** (`#endif` at EOF) | ✓ |
| the ONE case (VERBATIM sed :351-:366 THIS pass, block quoted BELOW the table) | **:352** header + **:364** lone CHECK; whole-file `CHECK` grep = 1 — ALL inside the block | ✓ |
| NAME/shape pin ONLY | 1 TEST_CASE / 1 tag / 1 CHECK is grep-face ONLY: **the assertion count entering docs = the RUNNER's tail line, NEVER grep arithmetic (17p lesson)**. Scratch receipt for the shape ONLY (runner-measured at the rehearsal, NOT a forecast — build.sh at the row RE-GREPS its own run): tail `All tests passed (1 assertion in 1 test case)`, `gate -l` → `1 test case`, gate rc=0 | ✓ |
| Table face REAL (contrast 18e commented hopopts) | **:337-:341** live `#ifdef BUILDING_SO` / `SO_PUBLIC const BaseApi* snort_plugins[]` / `#else const BaseApi* cd_gre[] =`; table body :342-:345 `&gre_api.base, nullptr`; `gre_api` static CodecApi at :315 with real `mod_ctor`/`mod_dtor` | ✓ |
| ground ships NO separate gre suite | `ls src/codecs/ip/test/` = CMakeLists.txt + checksum_test.cc ONLY — gre's suite IS the :351-:366 embedded block (the checksum suite is CppUTest-dialect, 18b precedent, box-dead) | ✓ |
| sids resident | ground `codec_module.h:93-:98` `DECODE_GRE_* = 160..165`; **Rust side ALREADY LANDED** `codec_module.rs:107-:112` (grep THIS pass, h:-cite comments present) — the row adds ZERO new sid constants | ✓ |
| row-vs-subrow call | **SINGLE row** 366 L — smallest codec row since 18c; it is NOT about scale, it is about banking the gate-change recipe | ✓ |

The ONE TEST_CASE block VERBATIM (ground sed :351-:366, re-read THIS pass; line-end markers added, body byte-verbatim):

```cpp
#ifdef UNIT_TEST                                              // :351
TEST_CASE ("Validate error check for raw_len greater than GRE_HEADER_LEN", "[cd_gre]")
{
    GreCodec grecodec;
    const uint8_t raw_in = 0;
    uint8_t raw_len = GRE_HEADER_LEN + 1;
    ip::IpApi ip_api;
    EncState enc(ip_api, ENC_FLAG_VAL, IpProtocol::GRE, 0, 0);
    uint16_t size = 1;
    uint8_t t = 0;
    Buffer buf(&t, size);
    Flow *flow = nullptr;

    CHECK (false == grecodec.encode(&raw_in,raw_len,enc,buf,flow));   // :364
}
#endif                                                        // :366
```

## 1. Naming judgment — `gre_harness` PINNED

`grep -rn 'gre_harness'` NEXT.md + PORTING_PLAN.md + KNOWN DEVIATIONS.md + all tools/*/PLAN.md = **0 pre-hits** (measured THIS pass): pre-unnamed like ext/tun. Pin = `tools/gre_harness/` (one-word lineage semantics csum/vocab/eth/ext/tun). NEVER `ip_harness` — ip/ also holds udp/icmp4/icmp6/esp/pgm/frag/auth rows (NEXT thereafter-order census).

## 2. Copy tree = tun donor VERBATIM + EXACTLY 1 row cp + FRESH-cp census MEASURED AT 2 (drift vs NEXT scoping, recorded honestly)

Includes per-TU (ground cc:22-:35): config.h, codecs/codec_module.h, framework/codec.h, log/messages.h, log/text_log.h, main/snort_config.h, protocols/gre.h, checksum.h (same-dir).
- **LIVE-CONFIRMED MISS** `protocols/gre.h` 50 L md5 `7b07af8eb173251c944960c891bae79e` — scratch `E4_firstline.txt`: `cd_gre.cc:30:10: fatal error: protocols/gre.h: No such file or directory` (wall #1).
- **LIVE-CONFIRMED MISS** `ip/checksum.h` 284 L md5 `b43628f369e16b1d5c093ff447d3e954` — NEVER cp'd into ANY donor (csum row was Rust-inline; find over copy trees = 0). Wall #2 face: scratch `E12_minface.txt` (gre.h in, checksum.h out): `cd_gre.cc:32:10: fatal error: checksum.h: No such file or directory`.
- **NEW MEASURED DRIFT vs NEXT scoping** (`utils/endian.h` 76 L as "~3 fresh cps"): **endian.h is NOT in cd_gre's transitive compile closure at the tun tree** — grep `endian` in ground `checksum.h` = 0 hits; scratch E13 face (ONLY gre.h + checksum.h cp'd, endian.h ABSENT): `rc=0` syntax-clean. Verdict: **EXACTLY 2 fresh cps**; cp'ing endian.h stays OPTIONAL belt-and-braces (the cp itself is byte-harmless, md5 `b81ef484ef96842c6e86db85dad5ead8`), the row's build.sh find-count assert is the authority. Copy tree = 86 (tun, incl its 2 fresh cps) + 1 row + 2 fresh = **89** sources (find -type f ! -name '*.o' assert at the row; re-census any transitive face in the FULL compile, scratch E1 already proved face CLOSED: plain compile rc=0 stderr 0 lines with the 3-cp face).
- Donor integrity spot-pins inherited: codec_module.h `3f3bd927…` · snort_config.h `638120b5…` · geneve.h `10cfe860…` · teredo.h `b7adb3d8…` · active.h `ce608579…` · `test ! -e copy/codecs/codec_api.{h,cc}`.

## 3. Rust posture — FLAT landing, names/sids ALREADY resident (zero rename landmine)

- Future TU `src/codecs/cd_gre.rs` (flat convention; TRUE name — file base `cd_gre` == extern `cd_gre[]` :340, no hopopts-style drift tripwire).
- Ladder: STATIC_CODEC_EXTERN_NAMES **"cd_gre" ALREADY resident codec_api.rs:110** (sed :108-:112 THIS pass shows it between cd_geneve/cd_gtp) — NEVER re-touched (tunnel-trio face inherited).
- sids: all six `DECODE_GRE_*` ALREADY at codec_module.rs:107-:112 (cite in §0) — the Rust row wires behavior only.
- PID `IpProtocol::GRE = 47` (protocol_ids.h:66/:102 ground); event call sites for the DEC arms: cc:171 (160 LT_GREHDR) / :189 (163 INVALID_HEADER) / :241,:248,:255 (164 V1_INVALID_HEADER) / :270 (162 INVALID_VERSION) / :276 (160) — grep-verified receipt `gre_event_calls.txt`.
- `tunnel_mask` still NO Rust twin — rides the config-row ruling (18c max_ip6_extensions precedent, 18f codification), queue for KNOWN DEVIATIONS at the Rust row, NOT this C row.
- In-crate #[test] count stays 0 in the new TU (suite face = `tests/gre_parity_test.rs` at the port row — vectors replay, NEVER in-crate).

## 4. THE GATE CHANGE + two-lineage census (rules pinned at NEXT :355-::379, re-cited and MEASURED here — counts NEVER typed)

Live census THIS pass: `md5sum tools/*/gate.txt` over exactly **24** tracked gate.txt → exactly **9** holders of `4826fc2233044a2d5429413faf0ae1af` (fcap/fcapi/fconf/fcshare/finspect/flog/fmod/fpolicy/fsvc — byte-frozen, NEVER edited to "rejoin"). At 18g, per the pinned rule (NEXT "THE GATE CHANGE" §, cites re-echoed):
1. build the REAL Catch gate for cd_gre.cc (shim route, §5 — recipe dual-precedent banked);
2. rfind + brace-balance excision of the TRAILING block ONLY (:351-:366) on the PROBE side; early :34-:36 stays armed (§6);
3. duplicate-symbol rule: UT-compiled .o in the GATE link, plain .o EXCLUDED (§6, E9 face proves WHY);
4. the runner tail becomes the new chain anchor; post-change holder census is RUNNER-MEASURED at the row — typed numbers BANNED here (the 115/23 forecast face stays dead);
5. the 9 legacy holders stay byte-frozen at 4826fc22; the census honestly counts **two md5 lineages** from the gre row on (gre's gate.txt adds a 25th tracked gate with its OWN md5 — even that count comes from the loop at the row, not from this page).
- 18g = FIRST real codec-row Catch gate = FIRST chain break after 14 straight — the session ritual (fmod fresh rebuild, gate 4826fc22 tail verbatim re-read) keeps the frozen-lineage proof runner-measured at the row, NEVER inferred.
- gre harness ships a gate.txt (contrast tun's `find -maxdepth 1 -name 'gate*' == 0` self-check — here the flip: build.sh asserts the gate artifact EXISTS + gate run rc=0 + tail grep, and the 9/24 frozen census assert must be UPDATED to the two-lineage face AT the row, not in this pre-scan).

## 5. Shim-route judgment — dual precedent, scratch MEASURED both sides of the fork

Ground `catch/snort_catch.h` is NOT a plain catch.hpp alias: it wraps `#include "catch.hpp"` under `#pragma GCC visibility push(default)`, then `#undef TEST_CASE / #define TEST_CASE(...) MAKE_SNORT_TEST_CASE(...)` → each case becomes a `static` fn + a `snort::TestCaseInstaller` ctor instance (SO_PUBLIC :42/:43) that requires an installer symbol PROVIDED BY THE MAIN BINARY's plugin plumbing. Our harnesses link NO plugin_manager/snort main → the ground header's TestCaseInstaller body is an UNRESOLVED U-face.
- **CHOSEN ROUTE (precedent 1, fmod build.sh :249 catch.hpp pull + :270 snort_catch.h heredoc shim `#pragma once / #include "catch/catch.hpp"`; precedent 2, fctx build.sh :60-:63 same shim + :403-:407 `catch_main.cc` CATCH_CONFIG_MAIN TU + :413 gate link shape)**: shim at `copy/catch/snort_catch.h` (so the ground `#include "catch/snort_catch.h"` :35 resolves VERBATIM in an unmodified ground TU under `-DUNIT_TEST`), vendored `copy/catch/catch.hpp` from rules_harness (md5 `74ef54e848cf843c99e3acdb94ce2b1a` re-summed at seed), plain Catch via catch_main TU — the TEST_CASE macro is NEVER remapped, so the ground block :351-:366 compiles verbatim on the gate side.
- Scratch MEASURED receipts: `E6_face.txt` — `-DUNIT_TEST` compile of the UNEXCISED ground file rc=0 both trials (shim closes the include); `E10_face.txt` — full gate link (catch_main.o + cd_gre_gateut.o + donor REAL .o face + witness_18f.o + witness_conf.o + stubs_18d.o, NO new witness) rc=0; `gate_rc.txt` rc=0; `-l` lists exactly the ONE ground case by name + tag (face-pin in build.sh, NOT an arithmetic assert).
- REJECTED alternative: ground installer route (define TestCaseInstaller as a witness) — drags main-binary Catch-global plumbing + SO_PUBLIC visibility face for ZERO benefit at a single-TU harness; the dual precedent already ruled this shape (fmod/fctx both shipped shim gates).

## 6. Excision + duplicate-symbol rule — 17r recipe ADAPTED, both failure faces MEASURED at scratch

- **17r recipe cite**: fctx build.sh :367-:386 — `rfind("#ifdef UNIT_TEST")`, tail asserts, `s = s[:i]` (cut to EOF), brace-balance assert. gre adaptation: tail assert becomes `"[cd_gre]" in tail` and the head-count assert is **== 2** (fctx file_lib asserts >= 3 early fragments; gre has ONE early fragment + the block — measured `grep -c` = 2).
- **E7 face (scratch lesson, codified)**: cutting only to the block's closing `}` (not to EOF) leaves the orphan `:366 #endif` → measured `error: #endif without #if` (`E7_probe_excised.txt`). The 17r cut-to-EOF face is MANDATORY for the gre shape; E13/E8 faces prove the 17r-exact excision compiles rc=0 (probe side; early :34-:36 fragment survives — assert `"#ifdef UNIT_TEST" in s` post-cut).
- **DUPLICATE-SYMBOL face (E9, MEASURED)**: linking plain .o + UT .o together → `multiple definition of 'cd_gre'` at `.data.rel.local` (`E9_dup_first.txt`). nm defined-symbol census: plain = 1 symbol (`cd_gre`, nm_D_plain.txt), UT = 1 (same, nm_D_ut.txt), intersection = 1 → every link MUST carry exactly ONE face: GATE gets `cd_gre_gateut.o` (-DUNIT_TEST, UNexcised); PROBE gets `cd_gre.o` (plain, excised). build.sh census at the row: `nm gate | grep -c ' cd_gre'` == 1 (scratch gate_cdgre_once.txt = 1 pre-receipt).
- probe link face MEASURED: excised plain .o + donor REAL .o's (codec/ip/sf_ip/util_cstring/util/text_log/module, tun :209 list) + witness_conf.o + stubs_18d.o + witness_18f.o link rc=0 and the walk probe RUNS (E11 face ok, `probe_walk_out.txt`).

## 7. Witness posture — EXACTLY ZERO new witnesses (witness_18f carries; the row is witness-CLEAN)

cd_gre's U-census carries exactly **1** `SnortConfig::tunnel_bypass_enabled` U-line (nm_tunnelbypass_plain.txt = 1; call site ground cc:280-:281 `codec.conf->tunnel_bypass_enabled(TUNNEL_GRE)` → `codec.tunnel_bypass = true`) — resolved by the TRACKED witness_18f.cc (md5 `ea1f79f3…` re-verified THIS pass) carried across from tun; gre's mask arm rides the same observable table: TUNNEL_GRE **0x40** (TunnelFlags block snort_config.h :119-:128 re-sed at seed → `tunnel_flags_block.txt`: GTP :119 0x01 / TEREDO :120 0x02 / GRE :125 0x40 / VXLAN :127 0x100 / GENEVE :128 0x200). SFDAQ arm stays pinned false (unlinked). NO witness_18g file; witness_conf.cc heredoc-regenerated byte-ident `4dd91018…`.

## 8. Probe + vectors design — dual-face carry, arms MEASURED from ground, values NEVER typed

- **FACE-A** (walk): scratch probe_simple MEASURED `LOAD gre type=0 size=112 mod_ctor=1` — gre carries a REAL mod_ctor (contrast 18f teredo=0 asymmetry arm); in-probe `PluginManager::load_plugins` witness face inherited from tun probe.cc (print-then-pin discipline: values printed, build.sh greps, NEVER typed into docs).
- **DEC face**: arms drawn ONLY from the measured event/call census (§3 cites): short-dgram → EV 160 (cc:171), bad-header → 163, v1 bad-offset trio → 164 (cc:241/:248/:255), bad-version → 162 (cc:270), plus the second LT_GREHDR guard in the update path (cc:276); bypass arms mask-0x40 vs mask-0 face (ground tunnel_mask=0 default → bypass=1 arm, 0x40 set → bypass=0 → decodes on, next-header arms via gre.h `GREHdr::get_protocol_id` ntohs face); encode-false face = ground block's own subject: scratch gate REHEARSAL ran the ground case green (runner tail line in `gate_tail_real.txt`, rc=0 — receipt, NOT a docs forecast); the failing guard INSIDE encode (cc:127 body: `!buf.allocate(raw_len)` allocate-gate vs the block's 1-byte backing `Buffer buf(&t, 1)`) is which-face-returns-false territory — the arm is measured at the row's probe run, NEVER guessed here. Vector COUNTS/md5s: measured at first run + md5+wc pinned, exactly the tun face — NO arithmetic typed here (17p hard-rule).
- **GATE face (NEW at 18g — the third output stream)**: `gate.txt` runner output tracked (contrast tun PLAN 8 zero-gate face); O0==O2 arm rehearsed: scratch gate vs gate_O2 outputs byte-ident (cmp, O0O2_face.txt) — the O2 UT-compile + link face carried.
- hygiene: all-decimal vectors, `0x`-grep 0 on tracked faces (tun rule); nm per-TU receipts `nm_U_cd_gre*.txt` at the row (scratch pre-receipts: plain 28 / UT 50 unique U-lines — the +22 delta is the Catch registrar family (AutoReg/AssertionHandler/StringRef/makeTestInvoker/ITransientExpression + __cxa pair, `nm_U_diff.txt`) ALL resolved by catch_main.o in the gate link (E10 rc=0), plus Buffer/EncState ctor U-lines from the block body).

## 9. Landmines, frozen-donor pins, risks, stageables

- **Landmine posture ZERO (asserted)**: `grep -c cd_gre` = **0** in vocab witness_stubs.cc AND codec_harness stubs.cc (measured THIS pass); no witness block freezes the name → no FACE-II rehearsal (18e rule); vocab D-table census stays 4, ext retired stays 3.
- **Probe must pull NO codec_api object** (ext face-A nm rule: zero `load_codecs`); the STATIC_CODECS extern `cd_gre` at codec_api.cc:52 (hit-list cite echo, sed-verified at seed in vocab copy face) stays the dormant-ladder record, not a link edge.
- **fctx 17r dup-symbol precedent stays frozen**: gre must NOT re-touch fctx's file_* UT .o face; the gre gate link is its OWN link (fctx gate lineage 42349372 never joins anything — shape reference only).
- risks ledger: (R1) the ground embedded suite IS the row's gate — if the runner output ever shows 0 cases, silent-green risk → build.sh MUST grep `-l` case-name + tail line, not just rc; (R2) excision-face drift: any ground edit touching the trailing `#endif` re-arms the E7 face — rfind asserts catch it; (R3) shim drops the visibility pragma + installer remap — DOCUMENTED deviation face for KNOWN DEVIATIONS at the row (the gate is a harness stand-in for ground's plugin-catch, same disclosure as fmod/fctx shims); (R4) chain-change census asserts at tun/ext build.sh (:72-:75 / :50-:53 cd_gre anchors) stay UNTOUCHED at 18g — they assert ground anchors, not harness faces; they only die if the ground file reflows (re-ground if so); (R5) NEVER typed counts anywhere in docs (17p) — §0/§4/§8 carry scratch receipts as scratch receipts, the row's build.sh owns every live number.
- frozen-donor re-md5 census @ row (five+ diff-0 pins, tun PLAN 9 face inherited): vocab witness_stubs `9fad7e9d…` · vocab vectors `5da70e82…` · codec stubs `be9bdd0b…` · eth stubs_18d `f4afd35f…` · ext witness_conf `4dd91018…` · tun witness_18f `ea1f79f3…` + tun vectors `2a792479…`/faceA `81602890…` (tun row face undisturbed — gre adds NO edit to tun).
- Tracked stageables (target EXACTLY 7, tun face inherited): `PLAN.md · build.sh · probe.cc · probe_dec.cc · catch_main.cc (NEW — gate TU, tracked like fctx's) · vectors.txt · vectors_faceA.txt`; NO witness file; ignored: copy/ · o2/ · binaries · *.o · witness_conf.cc (heredoc-regen byte-ident) · ut .o faces · gate · gate.txt (tracked? — tun had NO gate.txt; at 18g per NEXT rule (4) the runner tail IS the anchor → `gate.txt` TRACKED like fmod's 24 holders, verify against the 9/24 holder census face AT the row) · vectors twins · nm_U_*.txt · E*.txt · cp_audit_ok.txt · *.log.
- wiki: READ-ONLY, untouched all recon pass.
