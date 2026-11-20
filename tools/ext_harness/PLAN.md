# ext_harness PLAN — row 18e: IPv6 extension chain (cd_hop_opts + cd_dst_opts + cd_routing + cd_mobility + cd_igmp, 721 L, probe-only)

Seeded in-repo from `/opt/data/cache/scratch/row18e/recon.md` (53 L) READ-ONLY port recon @ ground snort3-src `fe29cbe7403acc0dd428065a69d8f29cc311c18e` (untouched all pass; `git -C /opt/data/snort3-src log -1` re-measured at seed time). Port repo HEAD `433edf541e01fc1f1b0e32e5225eece9e0a169c0` (18d docs close-out; lineage head = **eth_harness** per donor census; gate chain 12 straight -> 18e = 13th). Every number below was re-measured THIS pass (scratch `row18e/` + fresh FACE-A/DEC/FACE-II links against the LIVE eth donor tree — byte-ident to the scratch pins, receipts vA/vD/v_ii2 at scratch `extprobe18e/`). Ground repo untouched (READ-ONLY). Donor lineage head: `tools/eth_harness/` (18d) — donor copy face VERBATIM + row 5 delta; vocab `witness_stubs.cc` md5 `9fad7e9d7a278fbc2ee82c233f86e774` + vocab `vectors.txt` md5 `5da70e82416b6f769af8177d859331e7` byte-frozen (re-pinned in build.sh).

## 0. VERDICT: 18e scope CONFIRMED (721 L five ip-ext codecs, zero suites — own wc/grep re-measured at seed)

| claim | measured | verdict |
|---|---|---|
| ip/cd_hop_opts.cc 143 | md5 `ec3b0bed51c16c7eab9939aa484b0cb0` | ✓ |
| ip/cd_dst_opts.cc 134 | md5 `033def126e4e32c6db272629fe91dde7` | ✓ |
| ip/cd_routing.cc 163 | md5 `811d85c5dbe45398a10c97efcdb0291f` | ✓ |
| ip/cd_mobility.cc 143 | md5 `a053ea4f83cb866e9267d610c1ed08d2` | ✓ |
| ip/cd_igmp.cc 138 | md5 `9dfbc89efc2a1eb7ea4861dca69fd826` | ✓ |
| TOTAL 721 | 143+134+163+143+138 = **721** (sum asserted in build.sh) | ✓ |
| gate material 0/0/0/0/0 | grep TEST_CASE/TEST_GROUP/^TEST(/UNIT_TEST per file = 0 on all five | ✓ |
| ip/test ships no suite units in row files | ip/test = checksum_test.cc 201 L + CMakeLists 1 L = 202 (18b-translated CppUTest face); zero suite units inside the five row files -> probe-vectors-only, 4th time (18b/18c/18d precedent) | ✓ |
| include closure ZERO fresh cps | all five TUs need ONLY eth-donor-resident headers; **CORRECTION to NEXT.md:270-:272**: cd_igmp.cc has THREE includes only (config.h :21, framework/codec.h :24, codec_module.h :25) — NO main/snort_config.h (igmp rides snort.ip_api, not SnortConfig). receipts E4_row_cd_*.txt rc=0 x5 EVERY build | ✓ |

Vectors count correction at seed: scratch recon §1 wrote "faceA 10 L / dec 31 L" — the actual wc-measured files are **faceA 9 L, dec 27 L** (md5 pins identical); the harness pins the MEASURED numbers (17p lesson: measure, never type).

## 1. Naming judgment — `ext_harness` PINNED

`grep -rn 'ext_harness'` NEXT.md + PORTING_PLAN.md + all tools/*/PLAN.md = 0 hits (measured at seed): the dir name was PRE-UNNAMED. Pin = `tools/ext_harness/` ("extension chain" — matches the one-word lineage semantics csum/vocab/eth; row label "the IPv6 extension chain", NEXT.md:257). Precedent for pin-over-pre-name: 17v pinned `fcapi_harness` against NEXT's stale "fapi_harness".

## 2. Copy tree = eth donor face VERBATIM + EXACTLY 5 row cps (delta = zero new cp)

Donor = `tools/eth_harness/copy/` built face carried VERBATIM (cp -a) — THE finding of the recon: the 18e five row TUs need ZERO fresh cps/grafts/surgery (include closure fully resident; E4 face rc=0 x5). Delta = exactly the 5 row cps staged into `$C/codecs/ip/`; copy tree = 76 + 5 = **81 source files** (find -type f ! -name '*.o' asserted). Donor integrity spot-pins: codecs/codec_module.h md5 `3f3bd927…` + `test ! -e $C/codecs/codec_api.h` (the FACE-flip precondition — the DONOR carries NO codec_api TU and ZERO cd_*[] stub tables, eth build.sh :380-:381 face). Row cps cmp byte-ident vs ground.

## 3. Probe faces (both TRACKED; measured arms — NEVER typed)

- **FACE-A (CHOSEN)** `probe.cc` 21 L (md5 `af4c83fcd6845898c29784249bcb7edf`): table walk over the five REAL tables via the load_plugins *witness in probe* -> `vectors_faceA.txt` **9 L** md5 `0fa79b534d2a598b2befb047c95c3579` (5 real LOAD names ipv6_hop_opts/ipv6_dst_opts/ipv6_routing/ipv6_mobility/igmp + `LOADS 5` + API/HELP arms `size=112 ver=1900547` CDAPI carry + igmp `mod_ctor=1`).
- **DEC face** `probe_dec.cc` 48 L (md5 `35d7f771c450657c0df6ffc313dc76e2`): decode arms, R6 var-before-printf -> `vectors.txt` **27 L** md5 `da21842980d042d5871edeaaf502049e**. EVs all match the LANDED CodecSid enum (codec_module.rs :133=272, :144=283, :213=455, :219=461, :233=475 — 18e NEVER re-walks; C-face literal greps: `DECODE_IPV6_TRUNCATED_EXT = 272` h:123, `DECODE_IPV6_TWO_ROUTE_HEADERS = 283` h:134, sed h:208/:214/:228 arms). Quirks pinned by arms + cites, NEVER unified: hopopts `HOP short7 -> 0` (cc :63) + `HOP lyr>len -> 0` (:74-:76) vs dstopts EXCESS-without-return (cc :63-:64, MEASURED grep return=0 in :63-:65); mobility `MOB badpayl -> 1` returns TRUE even with event 475 (cc :90 then :92 next=60); routing `ROUTE t0 -> EV 116 461 + EV 116 283` (type0 ladder, next=43); igmp rules=1 sid0=455 (cc:34- RuleMap, :95 mod_ctor, table mod_ctor :118).
- Link (both faces) = donor REAL-cp .o's (codec/ip/sf_ip/util_cstring/util/module) + 5 row .o + probe .o + **stubs_18e.o** + eth witness_conf.o + eth stubs_18d.o. **O0==O2 byte-ident BOTH faces** (cmp asserted); hygiene: zero `0x` anywhere. witnesses copied from the DONOR face (witness_conf.cc md5 `4dd91018f8439d706ba666c6f18c9152` re-pinned; queue_event EV-printer rides eth stubs_18d.cc).

## 4. THE LANDMINE — cd_hopopts dup: 18a-INVERTED retirement, E6 PROVEN EVERY BUILD

Frozen face: vocab `witness_stubs.cc:14` = `extern const BaseApi* cd_hopopts[]; const BaseApi* cd_hopopts[] = { &stub_hopopts, nullptr };` — names frozen by vocab vectors:25-:28 + Rust `codec_api.rs:82-:85` (CD_*_STUB records). Real def: `ip/cd_hop_opts.cc:137` (dead-comment BUILDING_SO arms :134-:138).
- **E6 collision receipt EVERY build**: co-link real `cd_hop_opts.o` + frozen `witness_stubs.o` MUST fail; first line matches `multiple definition of .cd_hopopts` -> `E6_hopopts_dup_collision.txt` (grounding grep: first line of the .txt is the dup line).
- **Own stubs = `stubs_18e.cc`** (md5 `a700f77ef7f1ff718f1ae9626f10b826`, 14 L): frozen vocab MINUS line :14 PLUS one `RETIRED at 18e` marker — **diff-0 proof in build.sh** (diff vs frozen = exactly one `<` (the :14 def) + one `>` (marker); python replace-check). nm face: stubs_18e.o defines EXACTLY 3 dormant tables cd_ipv4/cd_ipv6/cd_tcp, ZERO cd_hopopts.
- **THREE-FACE CENSUS pinned** (fmod trio_retirement_census precedent): frozen vocab face = 4 D tables; retired-stub face = 3; 18e real-TU face = 5 D tables cd_hopopts/cd_dstopts/cd_routing/cd_mobility/cd_igmp (nm asserts).
- **FACE FLIP = why the probe NEVER pulls codec_api.cc** (rule asserted: FACE-A + DEC link lists contain zero codec_api object): FACE-II rehearsal (landmine face, generated files only): ground `codec_api.h` cp'd to `cpc/codecs/` (md5 `df2bc9d1…`, ground-ident; the DONOR LACKS it — asserted), codec_api.cc + 4 no-op cd_* .o compiled, driver `probe_lc` HEREDOC-generated (md5 pinned at generation), link with stubs_18e.o rc=0 -> `LOAD unknown`(cd_default) + `LOAD cd_ipv4_stub/cd_ipv6_stub/cd_tcp_stub` + **`LOAD ipv6_hop_opts`** = the frozen vocab stub line FORKED to the real name (codec_api.cc:34 extern + :82 load_plugins(cd_hopopts) FREE-resolve, proven every build). vectors_faceII.txt is a BUILD RECEIPT (ignored), not a tracked pin — the tracked pins are the face-A/DEC faces the rule protects.

## 5. nm residue census per-TU (re-run every build; receipts nm_U_cd_{hop_opts,dst_opts,routing,mobility,igmp}.txt)

U-line counts **11 / 11 / 10 / 10 / 21** (measured, asserted). App residues: hopopts/dstopts {codec_event, CheckIPV6HopOptions, CheckIPv6ExtensionOrder}; routing/mobility {codec_event, CheckIPv6ExtensionOrder}; igmp {codec_event + full Module family (ctor 2-arg @ module.o, stats virtuals, get_global_count, vtable/typeinfo)} — ALL resolved by resident donor T defs (codec.o nm --defined-only T-checks for codec_event + CheckIPV6*; module.o T ctor). **ZERO new witnesses vs 18d.**

## 6. Rust posture (row lands with its pair; harness mirrors the flat convention)

`src/codecs/` FLAT today = cd_arp/bad_proto/default/eth/no_next/raw/checksum/codec_api/codec_module + mod.rs. 18e adds **cd_hop_opts.rs / cd_dst_opts.rs / cd_routing.rs / cd_mobility.rs / cd_igmp.rs** (C base names; tripwire note: extern name `cd_hopopts` vs file base `cd_hop_opts`). Call targets ALREADY resident: codec.rs check_ipv6_hop_options (:521) + check_ipv6_extension_order; parse_conf.rs hit_ip6_maxopts/max_ip6_extensions (18c). codec_api.rs **UNTOUCHED**: :82-:85 stub records frozen + STATIC_CODEC_EXTERN_NAMES already names cd_dstopts :102 / cd_igmp :116 / cd_mobility :118 / cd_routing :125 — real records land per row TU, NEVER rename/fork the stub consts. igmp = first 18e unit with mod_ctor/mod_dtor + own RuleMap (1 row, sid 455); its ip_api seam (DecodeData has NO Rust ip_api twin, codec.rs header note) = LEFT-OPEN ruling, goes in KNOWN DEVIATIONS at the Rust row (17v style).

## 7. Gate identity — 13th straight; ZERO-EDIT

build.sh asserts: md5 census = exactly **9** holders of `4826fc2233044a2d5429413faf0ae1af` among exactly **24** tracked tools/*/gate.txt; zero gate* artifacts in this harness (`find "$H" -maxdepth 1 -name 'gate*'` == 0); fmod oracle recipe greps from the COMMITTED fmod build.sh (csum/vocab/eth precedent). The 13th-straight claim rides the SESSION fresh rebuilds of fmod + vocab (session ritual OUTSIDE this script; logs scratch row18e/{fmod,vocab}_rebuild_18e.log: fmod gate `4826fc22…` + tail `All tests passed (114 assertions in 22 test cases)`, vocab `VOCAB_HARNESS_OK vectors=29` + vectors `5da70e82…` stable, 9-holder echo). cd_gre rule UNTOUCHED: anchors re-measured in build.sh (:34-:36 UNIT_TEST fragment, TEST_CASE :352, 366 L — 18e pre-digs NOTHING).

## 8. Stageables (EXACTLY 7 — check-ignore verified) / build-regenerated (ignored)

Tracked: `PLAN.md` · `build.sh` · `probe.cc` (21 L, md5 af4c83fcd6845898c29784249bcb7edf) · `probe_dec.cc` (35d7f771…) · `stubs_18e.cc` (a700f77e…, inversion drop of vocab :14 + RETIRED marker) · `vectors_faceA.txt` (9 L, 0fa79b53…) · `vectors.txt` (27 L, da218429…) [DEC face].
Ignored: copy/, cpc/, o2/, probe*, probe_dec*, probe_lc*, all regenerated *.o (incl. copy/**/*.o; stubs_vocab.o), witness_conf.cc, vectors_{O0,O2,faceII}.txt + vectors_faceA_{O0,O2}.txt, nm_U_*.txt, E4_*.txt, E6_*.txt, cp_audit_ok.txt, link receipts (linkII.txt, runII_err.txt), gate* (NEVER created), *.log. Frozen-donor md5 re-pins asserted: vocab witness_stubs.cc `9fad7e9d…`, vocab vectors.txt `5da70e82…`, codec_harness/stubs.cc `be9bdd0b…`, eth witness_conf.cc `4dd91018…`, ground codec_api.h `df2bc9d1…` (cpc face).
