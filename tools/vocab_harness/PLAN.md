# vocab_harness PLAN — row 18c: codec vocabulary (codec_api.{h,cc} + 4 cd_* TUs, 549 L, probe-only)

Seeded in-repo from `/opt/data/cache/scratch/row18c/recon.md` READ-ONLY port recon @ ground snort3-src `fe29cbe` (shallow clone; all history pinned at the tag). Port repo HEAD `9da7a5e` (18b docs close-out; lineage head fmod; gate chain 10 straight). Every number below was re-measured this pass (scratch `row18c/` + a fresh 18c-in-harness-form delta probe at `/opt/data/cache/scratch/delta_probe/` whose cp recipe equals THIS harness's build.sh, verbatim 17d donor list + row delta). Ground repo untouched (READ-ONLY all pass).

**CORRECTION vs scratch recon §5:** vectors are **29 lines** (`wc -l vectors_O0.txt` = 29; recon's prose "28 lines" miscounted — the file + md5 are the truth: 29 L, both levels md5 `5da70e82416b6f769af8177d859331e7`, byte-ident).

## 0. VERDICT: NEXT.md 18c scope CONFIRMED (549 L, path-correct dirs, zero suites)

| NEXT.md claim (:277-:282) | measured | verdict |
|---|---|---|
| codec_api.{h,cc} 147 | 26 + 121 = 147 (md5 `df2bc9d1…` / `77b4bd86…`) | ✓ |
| cd_default.cc 83 (misc/) | 83 (md5 `24af1182…`) | ✓ |
| cd_bad_proto.cc 98 (**ip/** not root/) | 98 (md5 `5b1624c2…`) | ✓ |
| cd_no_next.cc 116 (**ip/**) | 116 (md5 `5943bf61…`) | ✓ |
| cd_raw.cc 105 (root/) | 105 (md5 `d34183a1…`) | ✓ |
| TOTAL ~550 | **549** (`wc_5files.txt`) | ✓ |
| "all TUs <= 121 L" | max = codec_api.cc 121 | ✓ |
| "zero suites -> probe-vectors-only" | per-file census `TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST` = **0 on all 6 row files**; whole-tree: 1 Catch TEST_CASE = ip/cd_gre.cc:352 (paren form `TEST_CASE (`, grep needs `TEST_CASE[[:space:]]*(`) + 4 CppUTest files (ip/checksum_test 10T/3G, misc geneve 3/1, gtp 2/1, teredo 2/1 = **17 TEST / 6 GROUP**, 4 `add_cpputest` registrations) | ✓ |

Dir paths: cd_bad_proto + cd_no_next live in **codecs/ip/**, cd_default in **codecs/misc/**, cd_raw in **codecs/root/** — NEXT.md:278 prints some without dirs; harness copy tree mirrors ground layout, so no mapping games are needed.

Alternative scopes (recon §7, measured): cd_default alone (83, orphans the vocabulary: codec_api.cc's `extern cd_default` is what makes the cd_default array load-bearing), 4-TU deferral of codec_api.cc (428, loses the row title — load_codecs is the only plugin plumbing in the row), +codec_module.{h,cc} (889, crosses NEXT's own 18d boundary; codec_module.h already donor-resident at 17d), 5 harnesses (5x maintenance, zero added pins). **Keep NEXT's 549 L, ONE harness, dir `tools/vocab_harness`.**

## 1. Copy tree = 17d donor list VERBATIM + exact delta (zero-edit posture)

Donor cp = `tools/codec_harness/build.sh` recipe minus the catch pulls (probe-only: no gate, no -DUNIT_TEST => catch machinery dead weight; `grep -ci catch probe.cc witness_stubs.cc` = 0): framework/{codec.h,codec.cc,decode_data.h,base_api.h,counts.h,parameter.h,value.h,module.h}, codecs/codec_module.h, protocols/{ip.h,ip.cc,ipv4.h,ipv6.h,layer.h,mpls.h,protocol_ids.h}, sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_returns.h}, utils/{cpp_macros.h,bits.h,util.h,util_cstring.h,util_cstring.cc,util_net.h}, main/{snort_types.h,thread.h} + the four 17d printf grafts (config.h `#pragma once`, framework/api_options.h `#define API_OPTIONS 0`, log/messages.h decl-header, detection/detection_engine.h witness-header — all four greppable in codec_harness/build.sh).

Row cps (6): codec_api.{h,cc} + the 4 cd_*.cc at ground paths.

**Delta cp (E4 fatals force EXACTLY this, auto-loop re-proven in delta_probe):**
- `main/snort_config.h` — **real cp, no shim**: md5 `638120b51712c12ce847829308ac5a01` = ground = `tools/action_harness/copy/main/snort_config.h` (md5-ident precedent holder, 798 L). Its closure = **exactly 11 more real header cps**: recon's 7 (`target_based/snort_protocols.h`, `packet_io/active_action.h`, `framework/data_bus.h`, `framework/mp_data_bus.h`, `control/control.h`, `framework/mp_transport.h`, `helpers/lockless_ring.h`) + the 4 its own includes name (`framework/inspector.h`, `framework/ips_action.h`, `helpers/scratch_allocator.h`, `main/policy.h`, snort_config.h:35-:38). All header-only; compile clean -O0/-O2. **R2 note for later rows:** every later row carrying snort_config.h inherits this 12-file closure (one-time cost, this row pays it).
- `managers/plugin_manager.h` (md5 `a9242b711e2ca0ef9d4418dcc0caa014` pinned; = `tools/action_harness/copy/managers/plugin_manager.h` md5-ident real-cp precedent) + `managers/plugin.h` (`4c2ea065…`; closure = `<memory> <string>` + base_api.h — donor-resident) => 2 cps.
- **ONE graft:** `daq_dlt.h` — `find` over ground tree + host = ZERO hits (daqs/ ships daq_user.h DLT_USER 230 only, daqs/daq_user.h:29). Graft = `#define DLT_RAW 12` (fmod daq_common.h graft precedent). **DLT_RAW=12 CITE (R1 — vectors pin "DLT 12" twice: HELP string via ADD_DLT (cd_raw.cc:31-:32) + get_data_link_type v.emplace_back(DLT_RAW) (:62)):** value from real libpcap pcap/dlt.h (android.googlesource mirror, lines 112-114: DLT_RAW **14** on BSD/OS, **12** = the libpcap/libdaq convention). Never assume; the cite rides PLAN + build.sh.

Delta census: 6 row + 12 snort_config-world + 2 managers = **20 ground cps** + 5 new-path grafts (4 carried 17d recipes + daq_dlt.h). Fresh delta_probe (pure donor seed): cd_default/cd_bad_proto/cd_raw COMPILE-OK donor-only (cd_raw at the daq_dlt wall only), auto-loop of the two E4 fatals emits exactly the 12 + 2 lists above, then all 5 TUs OBJ-OK.

## 2. nm residue census (nm -C U, receipts nm_U_*.txt — harness re-runs per build)

| TU | snort-app residue | class |
|---|---|---|
| cd_default.o | none non-libstdc++ | CLOSED |
| cd_bad_proto.o | Codec::codec_event | RESOLVED by REAL 17d framework/codec.cc cp (def codec.cc:85) |
| cd_no_next.o | Codec::codec_event | same; hit_ip6_maxopts INLINE at snort_config.h:450-:451, max_ip6_extensions PUBLIC (:278) -> **NO access trick, NO snort_config .o** |
| cd_raw.o | none non-libstdc++ | CLOSED (get_data_link_type virtual) |
| codec_api.o | PluginManager::load_plugins + cd_default + cd_ipv4/cd_ipv6/cd_tcp/cd_hopopts (exactly 6 U-lines) | cd_default = the row's OWN .o; 4 arrays = LATER rows (18e/19 tail) => WITNESS ARRAYS (witness_stubs.cc, 4 stub BaseApi tables); load_plugins = WITNESS BODY in probe.cc (codec_harness/stubs.cc event-witness shape) => **witnesses = 4 cd_*[] + load_plugins ONLY** |

Probe-side-only residue (NOT row .o): SnortConfig ctor/dtor + 5 statics (logging_flags, log_quiet_bypassed, warning_flags, static_names_mutex, static_names) — witness bodies in witness_conf.cc (heredoc, build-regenerated, mirrors scratch witness_conf.cc md5 `7820246b…`); snort_config.cc itself NOT compiled (inspector/BUS world, 17z note). No all-inline analogy like 18b: 5 REAL TUs emit defs (Codec sub-vtables, ctors/dtors, file-static CodecApi tables, exported cd_* arrays) — residue classified per-TU above.

## 3. Probe link + E5 (backbone; scratch receipts = fresh targets)

Link = 5 row .o + {codec.o, ip.o, sf_ip.o, util_cstring.o} (17d donor objs, compiled fresh from -I$C) + probe.o + witness_conf.o + stubs.o (recompiled from the TRACKED `tools/codec_harness/stubs.cc`, md5 `be9bdd0b…`, byte-ident to scratch copy) + witness_stubs.o.

**EVAL-ORDER RULE (R6, vectors recipe, pinned in build.sh greps):** printf arg evaluation order silently interleaves side effects — scratch `printf("%d %u", c->decode(...), cd.next_prot_id)` read next_prot_id BEFORE decode ran (next=0 artifact; probe_fix.cc demo). Rule: **NEVER interleave a decode() return with post-decode field reads in one printf — store to vars first.** build.sh asserts: 0 printf-lines matching `next=.*c->decode`, and `bool r = c->decode` count 2 (raw v4/v6 var-first arms). scratch vectors_O0.txt == vectors_O2.txt **BYTE-IDENT, md5 both 5da70e82416b6f769af8177d859331e7, 29 L**: API lines (size=112 ver=1900547; cd_default features=0 = NO PLUGIN_SO_RELOAD, other three features=1), PID pins 256/53/77/59, DLT 12 x2 (raw), decode ladders (unknown->false; bad_proto -> EV 116 450 + true; NN short->false / ok->true lyr=8 bits=0x10000 printed-hex-as-10000 cnt=1 / maxopts -> EV 116 456 + false), raw v4->2048 v6->34525 bad->false, load_codecs() -> 5 LOADs (4 witness tables + cd_default). Hygiene gate (fmod build.sh:1101 VERBATIM recipe): no `0x[0-9a-f]{6,}` in vectors.

## 4. Gate identity — 11th straight is ZERO-EDIT (same oracle argument as 18b)

md5 census (measured): exactly **9 gate.txt hold `4826fc2233044a2d5429413faf0ae1af`** (fcap, fcapi, fconf, fcshare, finspect, flog, fmod, fpolicy, fsvc). NEXT.md:312-:314 "Ninth straight, 18c = 11th" holds IFF this harness is probe-only: it ships **ZERO gate.txt** (`test ! -e gate.txt/gate` asserted) and touches NOTHING in the 9 frozen dirs; frozen build.sh + frozen copy recipe + fixed ground sources => byte-ident stdout => byte-ident md5. fmod double-rebuild stays OUTSIDE this script (session ritual) on the csum 18b pattern; the pinned oracle proof is grepped from the COMMITTED fmod build.sh (`All tests passed (114 assertions in 22 test cases)` + `4826fc22…` lines) not from memory.

R4 (NO gate built): zero embedded suites per the §0 census AND CppUTest unbuildable on host, **double-walled** — geneve_codec_test.cc (CppUTest, `add_cpputest` misc/test/CMakeLists.txt:1) `#include "../cd_geneve.cc"` (:20): wall 1 `-I copy` only => dies FIRST inside the row TU (`cd_geneve.cc:26: fatal error: log/text_log.h`); wall 2 adding `-I $SRC/src` => the ground tree itself dies (`protocols/packet.h:27: fatal error: daq_common.h` — the DAQ SDK absence §1 cites). Re-proven EVERY build => E4_cpputest_fatal.txt two-段 receipt. A Catch gate over zero upstream cases would be the 17p fake-gate anti-pattern (csum_harness/build.sh:3-:8 R4 rationale carried).

R5 (RawData seam SAFE): grep 'daq_msg' over all 5 row TUs = **0 hits every file** => 17d "RawData drops daq_msg" deviation (codec.rs:9,:171) SAFE for 18c; seam defers to row 20 exactly as NEXT.md pins.

R3 (witness-array drift): the 4 witness cd_* arrays are re-exported by later rows — rule: **probe links witness_ arrays; later rows NEVER link their real array into this binary** (mirror of the cd_gre dup-symbol rule NEXT.md).

## 5. Scratch proofs -> harness translation (/opt/data/cache/scratch/row18c/)

wc_5files.txt · copy/ (64-file seeded tree incl. grafted daq_dlt.h; audit: ALL non-graft files byte-ident vs ground — harness re-audits via cp-delta greps) · nm_U_{cd_default,cd_bad_proto,cd_no_next,cd_raw,codec_api,probe}.txt · probe.cc (md5 e208a411…, staged VERBATIM) · probe_O0/probe_O2 + vectors_{O0,O2}.txt (md5 5da70e82…, 29 L pins fixed above) · witness_stubs.cc (md5 9fad7e9d…, staged VERBATIM) · witness_conf.cc (md5 7820246b…, becomes build.sh heredoc) · stubs.cc (md5 be9bdd0b… = codec_harness/stubs.cc verbatim — harness compiles the TRACKED codec_harness one, no second copy) · probe_fix.cc (eval-order demo, stays scratch) · E4_cpputest_fatal.txt (geneve wall-1 form; harness re-derives both walls) · dlt.h (empty fetch artifact, superseded by the §1 libpcap cite — NOT carried).

Stageables (exactly 5): PLAN.md · build.sh · probe.cc · witness_stubs.cc · vectors.txt. Everything else build-regenerated + gitignored (copy/, *.o, probe binaries, vectors_O0/O2.txt, nm receipts, witness_conf.cc, fatal receipts, audit receipts, logs). vectors.txt STAYS tracked (csum-style block, check-ignore-verified). **NO Rust lands this row; 18c R5 keeps the RawData deviation untouched — Rust-side row ships with its own later row per NEXT.md tail.**
