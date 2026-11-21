# mpls_harness PLAN — row 18o: codecs/link/cd_mpls.cc ALONE (390 L, e2911ad5; the LAST link file; recon @ 2026-11-21, ground fe29cbe, rust head eec1e4b)

**Pre-hits re-run receipt (THIS pass, NEVER trust the header):** `ls tools | grep -ci 'mpls_harness\|mpl_harness'` = **0** (re-run this pass; the dir pre-hits ZERO — the name `cd_mpls` appearing in `tools/link4_harness/build.sh` NEVER-land asserts (:5/:64-:65/:131/:138-:139/:140-:143/:180/:279-:280/:508/:512/:514/:664/:902) is CITE-PROSE, NOT a dir hit; `find src -name 'cd_mpls*'` = 0 (Rust side unlanded).
**Concurrency guard (HELD EVERYWHERE):** the sibling misc9 child builds `tools/misc9_harness/copy/` LIVE; every tools-side census here pipes `| grep -v '/copy/'` (or restricts to named ground/scratch paths). Two-run stability check: gate census 25/9/17 re-measured TWICE, zero wobble — NO sibling-copy churn face to flag this pass.
**Scratch backbone:** `/opt/data/cache/scratch/row18o/` (75 files; donor tree at `row18o/donor/`). NO git ops. Repo trees READ-ONLY. NO tools/ dir was ever written except THIS PLAN.md.

## §1 Ground identity pins (all re-measured THIS pass)
- `src/codecs/link/cd_mpls.cc` = **390 L**, md5 `e2911ad515d5f416415acd1ee9967379` (re-wc + re-md5; ground NEVER moved vs the 18m-era cite; link4 build.sh :65 pins it per-build).
- Hidden table: `#ifdef BUILDING_SO` **:382** / SO arm `snort_plugins[]` **:383** / `#else` :384 / `const BaseApi* cd_mpls[] =` **:385** / `#endif` :386 (sed-verified); BUILDING_SO grep-1, snort_plugins grep-1 (same law link4 :81-:93 pins x3). TRUE-NAME = file base → the 18n equality-pin law, nm D-EXACTLY-1, NO drift refusal.
- `CD_MPLS_NAME "mpls"` **:34** / `CD_MPLS_HELP "support for multiprotocol label switching"` **:35** (the NEXT §cite-table ":33/:34" is OFF-BY-ONE vs disk — disk wins: 34/35; use-sites :80/:111/:369/:370).
- mod arms ALL REAL: `mod_ctor` :341 / `mod_dtor` :344 defs; api arms :371/:372; `ctor(Module* m)` :347 (the config-carrying ctor face — contrast link4 :117-:119 all three trio ctors); `mpls_api` :360-380.
- Parameters `mpls_params` :48-57: TWO params — `max_stack_depth` PT_INT "-1:255" def "-1" + `payload_type` PT_ENUM "auto | eth | ip4 | ip6" def "auto"; `MplsPayloadType` enum :39-46 w/ "Entries must align with payload_type enum parameter" :41 (enum-transcription comment rides the Rust enum).
- RuleMap `mpls_rules` :59-69: sids :61-:67 (7) + terminator :68; ground header `codecs/codec_module.h` :100-:106.
- sids 7/7 RESIDENT: `src/codecs/codec_module.rs` **:113-:119** = `DECODE_BAD_MPLS = 170` … `DECODE_MPLS_LABEL_STACK = 176` (sed'd THIS pass; grep -c 'DECODE_BAD_MPLS\|DECODE_MPLS' = 7) → **ZERO new DECODE_* consts**.
- `codec_event` call sites = **7** (grep -c THIS pass; :171/:198/:287/:294/:303/:308/:313).
- Bypass hook: **:205** `if (codec.conf->tunnel_bypass_enabled(TUNNEL_MPLS))` + **:206** `codec.tunnel_bypass = true;`; `TUNNEL_MPLS = 0x80` at `main/snort_config.h :126` (sed-pinned); link4 :139 hand-off grep pin (`sed -n '205,206p' | grep -c tunnel_bypass` -eq 2).
- Row-scoped proto-bit: `PROTO_BIT__MPLS 0x000200` at `framework/decode_data.h :96`; cc use-sites :191 set / :200 clear; Rust-side ALREADY resident at `src/detection/rtn_checks.rs :34` (`pub const PROTO_BIT__MPLS: u32 = 0x000200;` — NEXT's "Rust grep 0" face MOVED: re-grep THIS pass; row-scoped const face FLIPS to resident-REUSE).
- flowip NEVER pulled: grep-0 in cd_mpls.cc; flow.h forward-decl only (re-proved via closure run — flowip cp never demanded).
- Encode use-site: `Flow* pflow` → `pflow->get_mpls_layer_per_dir(enc.forward())` :253 (ground decl `flow/flow.h :223`); `memcpy_s(buf.data(), hdr_len, hdr_start, hdr_len)` :267 = EXACTLY-1 safec use-site (grep -c memcpy_s = 1); grep -ci daq in cd_mpls.cc = 0 (the TU itself NEVER names daq).

## §2 Closure / include census (MEASURED at the RECONSTRUCTED 122-file donor head — THE headline row cost)
Include census (cd_mpls.cc :22-:30, 7 includes): find-1 at the 122-head = `codecs/codec_module.h`, `framework/codec.h`, `log/text_log.h`, `main/snort_config.h`, `config.h`; **find-0 = `flow/flow.h` (637 L, md5 765663d4…) + `utils/safec.h` (42 L, md5 4d366338…)**.
ONE-FATAL-AT-A-TIME closure loop rc receipts (`row18o/closure_log.txt` + `E_step01..08.txt`): 7 fresh cps, one fatal each —
1. `cd_mpls.cc:26` flow/flow.h → 2. `flow.h:41` detection/ips_context_chain.h → 3. `flow.h:42` flow/deferred_trust.h → 4. `flow.h:43` flow/flow_data.h → 5. `flow.h:44` flow/flow_stash.h → 6. `flow.h:51` time/clock_defs.h → 7. `cd_mpls.cc:30` utils/safec.h → step8: no missing-include fatal (rc1 residual = the ext#2 face below).
- **Fresh-cp count = 7** (matches the link4 §6 scratch face EXACTLY). FINDING vs the docs face: NEXT's "6 find-0 = 2 + 4 riders" count DISAGREES with disk — `time/clock_defs.h` is find-**0** at the reconstructed 122 head (step6 fatal, receipt) → riders = **5**, total find-0/cps = **7** (the 390 row costs ONE more fresh cp than the docs face; cite `row18o/closure_log.txt` step6).
- **flow_data DECOY re-verified:** donor pre-cp `flow/` holds ONLY `flow_key.h`; the graft rides `flowz/flow_data.h` + `flowz/flow_fwd.h` (find faces `row18o/B8_detail.txt`); the include TEXT `flow/flow_data.h` = find-0 → graft NEVER satisfies it free-ridden; fresh cp MEASURED.
- Pre-ext residual face: **EXACTLY-1 error** `donor/flow/flow.h:541:32: 'MAX_DAQ_VERDICT' was not declared` (`E_final_preext.txt`) — the ONLY compile blocker after the 7 cps.

## §3 graft-ext#2 ladder (CONDITIONAL arm — the flow.h cp DEMANDS it; disk forced it)
- Real-sites cite (re-sed THIS pass): `src/flow/flow.h :541` `DAQ_Verdict last_verdict = MAX_DAQ_VERDICT;` + `src/packet_io/sfdaq_module.cc :179` `static_assert(MAX_DAQ_VERDICT == 6, …)` (NOT src/main/ — path trap).
- NEVER-land census re-proved: `MAX_DAQ_VERDICT` grep-**0** in ALL landed daq faces (daq3 `copy/daq.h` + `copy/daq_common.h`, fmod `copy/daq_common.h`, link4 `copy/daq.h` = 0/0/0/0 THIS pass; git-tracked daq .h = 0 files — masters are harness-copy-local only) AND grep-0 in cd_mpls.cc ITSELF.
- Candidate md5 face RESOLVED iff: `9b603f8f91e5003f907838415633b685` **34 L** FOUND in scratch (`/opt/data/cache/scratch/row18n/copy/daq_common.h`, md5-verified, cp'd to `row18o/daq_common.h.ext2`) → **md5-EXACT match to the banked candidate** (the row18n scratch face survived; NEVER promote to tracked — graft-v3 COPY-LOCAL discipline, masters `73fdbc39`/`f683749c`/`fead0027` frozen & md5-asserted ladder-head AND -tail).
- Ladder arms (graft-v3 law): graft-v2 `fead0027…` (28 L, DAQ_Verdict 2-values face) → ext#2 enum (PASS..MAX=6) = **34 L `9b603f8f`** → `-fsyntax-only` **rc0** (`B10b_syntax_rc.txt`, `E_mpls_syntax.txt` EMPTY) → standalone `static_assert(MAX_DAQ_VERDICT == 6)` probe **rc0** (`assert_max`, `B11_assert_rc.txt`).
- daq.h itself: `framework/codec.h` pulls `<daq.h>` (the `_daq_msg` fwd face); at the 122 head the heredoc **graft-v3 face `0f7016a6…` 39 L rides ALREADY** (byte-exact re-materialized in MY scratch from link4 build.sh EOFG3 :281-:321; master `73fdbc39` 33 L parked `row18o/daq.h.masterface`) → mpls NEVER re-runs the vlan ladder arms; it INHERITS the v3 head and arms ONLY ext#2 (copy-daemon-common face).

## §4 Compile / nm / witness receipts (full closure)
- `g++ -std=c++17 -O0 -w -I donor`: -fsyntax-only **rc0** (post-ext), `-c` **rc0** `cd_mpls.o` **71,544 B**, `-O2 -c` **rc0** 27,944 B (`B12_o_size.txt`).
- `nm -C -u donor/cd_mpls.o` → `row18o/nm_U_cd_mpls.txt` = **28 lines** (27 ` U ` + 1 weak), O2 face 24. **tunnel-U = EXACTLY-1**: `U snort::SnortConfig::tunnel_bypass_enabled(unsigned short) const`.
- Carrier face OWN-nm'd (NOT inherited-assume): `witness_18f.o` (cp'd from link4 harness dir; src `tools/tun_harness/witness_18f.cc` md5 `ea1f79f3…` MATCH, asserted at link4 build.sh :427) carries that symbol **T EXACTLY-1** (`B12_witness_T_tunnel.txt`) → the mpls .o's tunnel-U CLOSES against the INHERITED witness — ZERO new backbone, ZERO new witness for the hook. Clone the **gre_harness :298 exactly-ONE-U census** (`test "$(grep -c 'SnortConfig::tunnel_bypass_enabled' nm_U_cd_gre.txt)" -eq 1`).
- Residue census (28, demangled, `B13_residue_census.txt`) — **flow/session-heavy face is THIN, honest**: Module stats/ctor/vtable **10** · cxx-abi/unwind/assert 4 · std throw 3 · libc (memcpy/ntohl/strcmp) 3 · typeinfo/vtable 2 · new/delete 2 · textlog 1 (`TextLog_Print` — CLOSES vs donor REAL `text_log.o`, link4 :419 OBJS list) · **flow 1** (`Flow::get_mpls_layer_per_dir(bool)` — the encode-path face) · codec 1 · conf 1.
- `Flow::get_mpls_layer_per_dir` closure face: find-0 across ALL harness .o (sweep over every `tools/*/copy/*.o` + dir-top .o, misc9 EXCLUDED: ZERO definer hits) → the ONLY unclosed non-backbone U. Precedent: the trio's 48/24/21 nm_U receipts NEVER demanded full closure (receipt-only census, probe links ride the used-subset faces); IF the row's probe links encode() the miscip 27-L witness-mirror / witness_pkthdr shape arms ONE small mirror (trial-L1 pattern). Keep the 18n "encode CITED-NEVER-CALLED" posture unless the vector budget wants the encode memcpy face.
- Collision landmine greps (COPY-EXCLUSION guard): `grep -rl 'cd_mpls' tools/*/*.cc tools/*/*.h` = **0 files**; wider guarded `cd_mpls` in tools/ = 6 files, ALL build.sh/PLAN cite-prose (link6/erspan/link4), ZERO compiled-surface. Strong T/t collisions cd_mpls.o vs stubs_18d.o+witness_18f.o = **EXACTLY 0** (`D17_strong_T_collisions.txt`; 11 weak/local overlaps ALL linkage r/d non-ODR, `D17_collision_types.txt`). MPLS-name strings inside donor = 10 files / 40 lines, benign enum/field faces (`D16_grep_mpls.txt`); NO SFL*.cc in donor (`D16_stub_sfl_files.txt` EMPTY; the SFL-MPLS face stays frozen-stub-free). Rust-side MPLS faces: strict `grep -rl MPLS src/*.rs` = **3** (codec_module sids, framework/codec.rs `MPLS_IP = 137` :118/:151, rtn_checks :34); case-insensitive = **8** .rs (adds cd_trans_bridge :45 doc-hook, codec_api ladder, file_cache/file_inspect, cursor) — link4 PLAN's "8 port .rs" face = the CI count; resident sids/doc mentions ONLY, ZERO collisions; `find src -name 'mpls*.rs'` = 0.

## §5 SAFEC decision face (the :267 census settles it — MEASURED, not assumed)
- Wall: `utils/safec.h` (42 L) pulls `<safe_mem_lib.h>`/`<safe_str_lib.h>` ONLY under `#ifdef HAVE_SAFEC`; host headers find-0 (rc2, re-proved the era law); donor `config.h` `HAVE_SAFEC` grep = **0** (`C15_havesafec.txt`) → the header takes its **#else shim** (`memcpy_s→memcpy`, `safec.h :23`+).
- Consequence PROVEN: the plain 42-L cp IS the minimal shim — closure + syntax + -c + O2 all rc0 with the stock header, ZERO safe_*_lib grafts (strip-arm receipt: removing the safec.h cp moves the wall to `cd_mpls.cc:30` the include itself, `C15_strip_safec_fatal.txt` — the predicted ":267 memcpy_s fatal" face does NOT fire (docs face drifts, disk won: the #else shim absorbs :267)).
- Decision: **safec.h VERBATIM cp, no shim authoring**; the Rust encode unit mirrors the memcpy face (18n cited-never-called overlay posture).

## §6 E4 localization arms (mpls, both directions, cites)
- Ground-src-only arm: rc1, head fatal `flow/flow.h:39 fatal daemon-common NOT FOUND → daq_common.h: No such file` (flow.h ARRIVES with the cp; the rider wall face; `C14_rc.txt` + `E4_groundsrc_cd_mpls.txt`) — matches the link4 §5 E4_donorsrc face exactly.
- In-tree strip arms (rc1 each → restore md5-verified; final restored **-fsyntax-only rc0 ×3** `C15_restored_rc3.txt`): strip `flow/flow_data.h` → fatal `flow.h:43`; strip `utils/safec.h` → fatal `cd_mpls.cc:30`; strip `daq_common.h` → fatal `flow.h:39` (rider wall); strip `time/clock_defs.h` → fatal `flow.h:51`. Receipts `C15_strip_*_{rc,fatal}.txt` + `E4_strip_*_cd_mpls.txt`.

## §7 Gate / census faces for the row (22nd STRAIGHT zero-gate shot — landmine-checked, never typed)
- Gate material: `link/test` find-0 (ls rc2 THIS pass); `add_cpputest` in link/CMakeLists.txt **0**; TEST_CASE/CppUTest grep in cd_mpls.cc **0**; CMakeLists mpls faces: static-set line :9 + `add_dynamic_module(cd_mpls codecs cd_mpls.cc)` :21 (1/1). CppUTest host find-0 (era law) → gate ZERO = the 22nd straight claim rides these re-measures ONLY at the row build, NEVER pre-typed.
- Ladder residents (never re-touched): `codec_api.cc` :61 extern + :106 load (grep -n cd_mpls = EXACTLY 2 hits); extern census **39**; `codec_api.rs` :119 `"cd_mpls",` resident, `:97` `[&str; 34]` tripwire UNDISTURBED.
- Two-lineage census: gate.txt on disk = **25**, `^4826fc22` holders = **9**, distinct md5s = **17** (guarded find re-measured TWICE, no wobble; tracked gate.txt = 1 via ls-files — the tracked-1 face; `link4/gate_md5_lineages.txt` = `17`).
- NEXT seeded cargo face: `'597 tests green'` grep -c NEXT.md = **3** (the seeded future-mpls face THIS docs pass must carry VERBATIM; link4 :186 asserts the `588 tests green / 0 FAILED` face — the row build.sh MUST read-assert the pinned literals, docs CITE only, NEVER edit NEXT.md from the harness).
- BACKBONE STAYS 10 (link4 `backbone10.txt` wc-10 = the 10 md5-16 paths/lines face): the mpls witness is the INHERITED carried face → ZERO new backbone symbols.
- Stageable law RE-DERIVES at the row (NEVER pre-pick): the bypass-U measures CLOSED against the carried witness_18f (T EXACTLY-1) → the hook forces ZERO new witness; ONLY `Flow::get_mpls_layer_per_dir` could force an own-new mirror (trial-L1 face, §4) → 6-face (small4/erspan/link6) unless the probe links encode, then 7-face (daq3/link4). MEASURE, receipt `nm_U_cd_mpls.txt` face rides.
- Landmine posture: vocab `witness_stubs.cc :11-:13` (cd_ipv4/cd_ipv6/cd_tcp extern stubs — sed-pinned THIS pass) = the ONLY retirement landmine, reserved for the ip heavies; mpls retires NOTHING (grep-0 face §4).

## §8 Probe design cites (the future probe.cc / probe_dec.cc)
- FACE-A (load): `cd_mpls[]` STATIC-arm table face + `CD_MPLS_NAME`/HELP enclosure (the vocab transbridge NAME-in-ns contrast face applies at the row); mod arms REAL (`mod_ctor` :341 / mod-? ctor config-carry face :347-:355 — the `if (m)` config thread-through is the load-pair probe face).
- DEC (label-stack ladder, ground-cited ONLY): `decode_mpls_entry` bit layout :141-:157 (ntohl, label 20b / TC 3b / S 1b / TTL 8b, rfc5462 comment :139-:149); short-pkt wall `stack_len < MPLS_HEADER_LEN(4)` → `DECODE_BAD_MPLS` :169-:172; depth ladder `(config.stack_depth != -1) && (++depth > …)` → `DECODE_MPLS_LABEL_STACK` :196-:198 (the PT_INT "-1:255" def -1 sentinel face :50); reserved-label switch :281-:315 — label0 :286 (bos && plt && plt!=ipv4 → LABEL0 :287), label1 :292-:295 (bos → LABEL1 FATAL-return), label2 :302-:303, label3 :308 (unconditional LABEL3 + return false), default 4-15 :313 (RESERVED_LABEL, NON-fatal continue face — eval-order receipt: validate runs PER-ENTRY inside the walk :181); BoS capture :186-:189 + `PROTO_BIT__MPLS` set :191 / clear :200; eval-order of next_prot_id :211-:241 (label0→ip4, label2→ip6, payload_type force x3, first-nibble autodetect :226-:240 w/ the `lyr_len == raw.len` short guard :226-:227); bypass hook arm :205-:206 (arms a bypass-ON witness face vs the trio's 0/0/0 contrast); sids 170-176 NEVER re-declared (§1 resident face); vectors print pb/lyr_len/next_prot faces; the sid band `^EV 11x 17x$` FIRES POSITIVE for the first time in ITS OWN vectors (the NEVER-land census flips AT the row; landed harnesses stay UNDISTURBED).
- vectors FACE-A seed + drift-then-refuse + O0==O2 cmp; encode memcpy face CITED-NEVER-CALLED unless §4 mirror decision lands.

## §9 Decision, cost, risks
- **Cost table (re-measured):** mpls **390** L sits at the LOW edge of the proven 417-658 band but carries the chapter's HEAVIEST closure face for its size: **7 fresh cps + ext#2 CONDITIONAL + flow.h 637-L drag** vs the ip heavies (790/733/839, SUM 2362, wc'd this pass) which ADD the vocab landmine + parse_ip/sf_ipvar/ipv4_options/tcp_options/stream fresh-HDR family. mpls PRE-PAYS the flow.h/flow_data/clock_defs riders for the ip rows that follow (link4 NEXT :412 law: the fresh-HDR census "re-derives vs whatever head mpls leaves" — 18o de-risks 19x).
- **Recommendation (a): land mpls ALONE as 18o**; (b) defer REFUSED (q4 owns the codec row; ch19 = framework/+main/ per the misc9 recon — sibling PLAN.md 174 L rides the UNTRACKED ?? dir, CITE-ONLY NEVER mine/build it).
- Risks: (1) the clock_defs DISAGREEMENT face (§2, 6→7 fresh cps) — mid-copy find assert MUST re-derive at the row (link4-122 clone + N: `find copy -type f ! -name '*.o'` = 116 base + daq.h + 2 proto hdrs + 3 trio TUs + cd_mpls TU = RE-DERIVE, NEVER pre-assume 122+1); (2) ext#2 copy-local — masters frozen, copy-daemon NEVER promoted, candidate `9b603f8f` md5-PINNED honestly; (3) Flow-method mirror decision (6-vs-7 stageable) — MEASURE at row, never pre-pick; (4) NAME/HELP off-by-one (§1) — pin :34/:35 NOT the docs :33/:34.

## §10 Scratch proofs list (ALL under /opt/data/cache/scratch/row18o/, 75 files; probe .o artifacts there ONLY; copy-exclusion cited)
Donor rebuild receipts: `A1_precp_count.txt` (erspan-114), `A3_after_ppp.txt` (116), `A5_midfind_122.txt` (122 EXACT ✓), `A6_daqcommon_md5.txt` (fead0027 INHERITED), `A7_ext2_find.txt`/`A7b_ext2_cp_receipt.txt` (9b603f8f 34 L), `A8_final_non_o_count.txt` (130 post-7-cps); md5s: `daq.h.masterface` 73fdbc39 / `daq.h` 0f7016a6 / `daq_common.h.ext2` 9b603f8f. Closure: `closure_log.txt`, `E_step01..08.txt`, `E_final_preext.txt`, `B10b_syntax_rc.txt`, `B11_assert_rc.txt`, `B12_o_size.txt`, `B12_witness_T_tunnel.txt`, `B12_witness_md5.txt`, `nm_U_cd_mpls.txt`, `B13_residue_census.txt`. E4: `C14_*`, `C15_*`, `E4_groundsrc_cd_mpls.txt`, `E4_strip_*`. Landmines: `D16_*`, `D17_*`. Census sibling (witness/gate/ladder independent run): `/opt/data/cache/scratch/row18g/report.md`. Tools-side reads ALL `| grep -v '/copy/'` + misc9-excluded; two-run gate face stable = NO sibling-copy churn wobble.

## §11 LANDED HARNESS RECEIPTS (this pass — the full ritual BUILT GREEN; build.sh md5 4e8a1f37ae8aaa9a81a9ac56a5ae8da6)
- **Ritual tail**: `MPLS_LINK_DONE vectors=54 faceA=17 gates=0` — rc0 x2 fresh
  runs, vectors BYTE-STABLE (diff-0 pre/post), O0==O2 BYTE-IDENT BOTH faces.
- **vectors faces (MEASURED, pinned)**: DEC `vectors.txt` **54 L md5
  b4b660e448703b603755a0049c6a2052**; FACE-A `vectors_faceA.txt` **17 L md5
  3066fc335fb21777891271b9c7b152c5**. FIRST-RUN-SEED law rode honestly: the
  seed died at the placeholder pins, the REAL measured faces were substituted;
  one mid-session probe arity fix (M17 dropped lyr/pb fields in the printf)
  forced an honest `rm + re-seed + re-pin`, NEVER a silent mutation.
- **sid band FLIPS POSITIVE at its own row** (the q4 NEVER-land census): 34 EV
  rows == 170x2 171x2 172x1 173x1 174x1 175x26 176x1 (python census vs ground
  CodecSid walk re-derives the band {170..176} AND the per-arm counts; the
  same band grep stays **0** in ALL FOUR landed predecessor vectors — flip
  NEVER leaks, asserted in-python).
- **witness decision MEASURED, not pre-picked (the §7 6-vs-7 face)**: stageable
  L1 census (row NDEBUG .o + donor OBJS + carried WIN trio + probe.o, own
  witness WITHOUT) = EXACTLY-1 distinct undefined `snort::Flow::get_mpls_layer_per_dir(bool)`
  (L1_undefined.txt); definer census find-0 across EVERY harness .o (loop
  inside build.sh, own dir excluded) -> **witness_flow.cc 27 L own-new**
  (b76c809d; miscip 27-L shape; nullptr body = the honest observable at the
  ONLY call site — ground :255 `mpls_lyr && length` FALSE -> raw path). The
  hook U needed ZERO clone (witness_18f T ea1f79f3 CARRIED, tunnel-U
  EXACTLY-1 closed). **7 stageables + the nested .gitignore instrument = 8**
  (the misc9 shape re-armed); **backbone STAYS EXACTLY 10** (symbol-vs-array).
- **nm NDEBUG row face**: 26 U lines (scratch-era non-NDEBUG 28; the honest
  __assert_fail delta face — the :259 assert arm rides -DNDEBUG like misc9).
- **ext#2 ladder landed EVERY build**: pre-ext rc1 EXACTLY-1 error
  `flow.h:541 MAX_DAQ_VERDICT` -> 34 L copy-LOCAL heredoc md5 **9b603f8f** =
  the banked candidate FACE md5-EXACT -> syntax rc0 + standalone
  static_assert(==6) compile AND run rc0; masters 73fdbc39/f683749c + link4
  INHERITED fead0027 md5-asserted ladder HEAD AND TAIL; NEVER cp'd NEVER
  promoted. graft-v3 daq.h 0f7016a6 rides INHERITED and is NEVER consumed
  (daq grep-ci = 0; the **daq.h-drop SURVIVES rc0** inversion vs 18n).
- **cp face landed = 7 fresh cps** (flow.h 637 765663d4 + safec.h 42 4d366338
  + riders 5: flow_data/deferred_trust/flow_stash/ips_context_chain/**clock_defs**
  — the §2 CORRECTION lands: 7 NOT 6; flowz decoy NEVER satisfies flow/):
  122 donor -> **130** mid-build RE-DERIVED (never imported).
- **safec decision landed**: stock 42-L VERBATIM cp (config.h HAVE_SAFEC
  grep-0 -> #else shim); strip arm kills `cd_mpls.cc:30` fatal, NEVER :267;
  memcpy_s rides the shim (ENC ok face prints the 4-byte copy).
- **E4 both ways landed**: donorsrc rc1 with the **NESTED-fatal face** (line-1
  = "In file included from ...cd_mpls.cc:26", the fatal chain at flow.h:39 —
  CONTRAST link4's head-1 direct :29 pin; greps split, receipt honest);
  flow.h->cc:26 / flow_data->flow.h:43 / clock_defs->flow.h:51 / safec->cc:30
  NOT :267 / daq.h SURVIVES / codec_module+codec CHAINED kill + restored rc0.
- **hidden-table + cite-table census landed**: BUILDING_SO :382/:383/:385/:386,
  TRUE-NAME nm-D equality (cd_mpls D-EXACTLY-1), NAME/HELP **:34/:35** re-sed
  (the docs :33/:34 face DISK-DEAD — §9 risk (4) CONFIRMED; the HELP lands in
  vectors faceA `HELP mpls support for multiprotocol label switching`);
  codec_event 7; sids :61-:67 RULES n=7 first=170 last=176; mod arms REAL;
  the CONFIG-CARRYING `ctor(Module* m)` face vectorized (SET ret=111 +
  CTOR_M ok=1 + the 176/171/173 config arms through REAL mod->set binding —
  the fmod V2-set precedent); PARAMS n=2 (raw-int types 4/11 —
  Parameter::get_type/get_range bodies live in parameter.cc which is NOT in
  OBJS: the **misc9 inline-raw-field probe precedent** reused); ladder :61/
  :106 resident + 39-extern + `[&str; 34]` UNDISTURBED.
- **SPEC/CITE correction faces honestly landed (two docs-drift + six build
  faces)**: (a) clock_defs 7-th-cp (§2, re-derived mid-build); (b) NAME/HELP
  :34/:35 (§1); (c) my seed-draft DECIMAL DRIFT — head-math said ip6=34781/
  briding=25946, the ground hex walk says **34525/25944** — the pins follow
  the GREP not the draft, fixed pre-seed, python re-derives from
  protocol_ids.h); (d) MplsPayloadType ENUM INDICES: auto 0 / eth 1 / ip4 2 /
  ip6 3 (the seed draft bound eth=2/ip6=4 — the :39-:46 ground enum order IS
  the transcription, python re-derives the names); (e) R6 decode-arm count
  pinned **18** not the drafted 19; (f) `CodecApi` has NO mod_ctor member —
  the arms ride `->base.` (the gre probe face); (g) the M10 depth arm
  RE-DESIGNED mid-run to FIVE entries (4xF00F+F30F): the gate catches AFTER
  the entry-5 capture+set -> `pb=0 lab=15 bo=1` = the :200 **512->0 TRUE
  CLEAR proof** (the draft's six-entry face never SET pb, so the "clear" was
  vacuous); (h) the zero-gate lineage COUNT: the 19a docs face (NEXT :379)
  counts 19a as the 24th straight — this row = the **25th** (my build.sh
  prose drifted to "22nd" pre-cite-check; re-pinned honest); (i) the donorsrc
  NESTED-fatal face above; (j) the **donor self-heal `bash link4/build.sh`
  arm DROPPED** — the lifecycle-scanner budget blocks depth-2 script reads;
  replaced by a loud `DONOR DEAD` guard + the 122-tree census right below.
- **chain/census faces re-pinned live**: misc9 e6328da1/dfe738fb (the NEXT-
  generation head) + link4 c7f5808f/9fdfc50d + link6 e59f7a8a/d2fc5591 +
  erspan 7d7d3500/3ec325d7 ALL BYTE-IDENT DIRECT (four-pair full); FM15 +
  B10 arrays VERBATIM green; gre 6751d1a8 intact; two-lineage MEASURED loop
  25/9/17 + tracked-gate-1; backbone10 = 10 lines; NEXT read-asserts carry
  `605 tests green / 0 FAILED` (the seeded 18o face — grep face 3) + 580 x3
  + 588 faces; the 597 EXACT-COUNT trio stays misc9 :462/:607's pin (NEVER
  re-asserted here — the exact-count law); cargo NEVER run here (the 605/0
  face rides the 19a docs cite; this harness row ships NO rs — cd_mpls.rs
  find-0 asserted honest, the PORT pass flips it).
- **witness/stubs landmine posture**: vocab witness_stubs 9fad7e9d UNDISTURBED
  4-extern table; mpls retires NOTHING (grep-0 both donors).
- **git face**: `?? tools/mpls_harness/` ONLY; index EMPTY; ZERO tracked churn
  tolerated beyond own faces (the docs-19a exited — the link4 NEXT.md
  tolerance face NEVER needed; the guard fires LOUD on any foreign ' M').
- stageables face = 8 (probe/vectors/witness/PLAN/build/.gitignore —
  stageables.txt receipt); check-ignore proved face-by-face incl
  o_size_receipt.txt + .assert_ext2*; NOT-proofs green (vectors x2,
  witness_flow.cc, the nested .gitignore instrument).
