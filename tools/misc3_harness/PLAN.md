# Row 18k PLAN — codecs misc leftovers TRIO: misc/cd_llc.cc + misc/cd_vxlan.cc + misc/cd_user.cc (RECON, probe-only)

Pre-hits measured at PLAN-0: `ls /opt/data/snort3-rust/tools` = 47 dirs, NO misc3* (`ls -d tools/misc3*` rc 1 "cannot access"); `grep -rn misc3_harness` over all *.md/*.sh = 0 hits. The name `misc3_harness` is FREE (NEXT.md never names it — its only tail mentions are the wc lines below). Ground = /opt/data/snort3-src @ fe29cbe7403 (re-verified `git rev-parse HEAD`). Port repo /opt/data/snort3-rust @ 76c1c16, `git status --porcelain` = 0 lines (CLEAN, no NEXT.md/miscip dirt — STOP-flag condition ABSENT). Next free PORTING_PLAN row slot verified: :89 = row 18j, :90 = `| 19 |` (row 18k slot is the 18i-cited "queue continues per order above" face — NEXT.md:465-468 scopes the misc tail AFTER the pair/heavyweights).

## §0 GATE CENSUS — ZERO gate material (18th straight honest face expected), STOP-flag NEGATIVE
Per-file greps MEASURED this pass (count per pattern): cd_llc.cc TEST_CASE=0 TEST(=0 UNIT_TEST=0 CppUTest=0; cd_vxlan.cc 0/0/0/0; cd_user.cc 0/0/0/0. misc/test/ listing = CMakeLists.txt + geneve_codec_test.cc + gtp_codec_test.cc + teredo_codec_test.cc ONLY — ALL THREE belong to the 18f trio (tun_harness already translated them: tun_parity_test.rs 7 up_tun_* + get_geneve_opt_data, PLAN-18f face). test/CMakeLists.txt add_cpputest x3 (:1/:6/:11) = the CppUTest dialect precedent (18f), ZERO cd_llc/cd_vxlan/cd_user suites ANYWHERE (find src -name '*test*' over misc = the 3 files). NO real Catch TEST_CASE material -> NO STOP-flag; contrast the 18g cd_gre embedded-Catch row (gre_harness gate.txt 6751d1a8) — this row is the small4/daq3/miscip ZERO-gate shape. Probe-only posture: harness ships ZERO gate.txt (`test ! -e gate.txt`).

## §1 GROUND TRIO CENSUS + DOORWAY (fresh measure, docs-18i wc VERIFIED)
wc MEASURED: cd_llc.cc 198 / cd_vxlan.cc 133 / cd_user.cc 167 = 498 L (MATCHES the docs-18i line "llc **198** / vxlan **133** / user **167**" NEXT.md :466-468). md5 per-file: llc df63cf75b1bf7642ca80b6a215a0f28c, vxlan c8479a2aa67ee6af89c22ecc8f763b7d, user 01e41407b300562c840b4f66a4da4e45.
Includes (sed census): llc = config.h + codecs/codec_module.h (:24) + framework/codec.h + log/text_log.h (FOUR); vxlan = config.h + framework/codec.h + log/text_log.h + main/snort_config.h + packet_io/active.h (FIVE); user = config.h + <daq_common.h> (:24) + daqs/daq_user.h (:26) + framework/codec.h + packet_io/sfdaq.h (:28) + packet_io/sfdaq_instance.h (:29) (SIX).
TRIO HEADERS DO NOT EXIST: `find src -name 'llc.h' -o -name 'vxlan.h' -o -name 'user.h' -o -name 'cd_llc.h'|cd_vxlan.h|cd_user.h` = EMPTY — the "vxlan.h 82L-ish + llc.h find faces VERIFY" claim from scoping is FALSE: zero header cps for the trio; ZERO header landmine.
Ground ladder (codec_api.cc): externs cd_llc :59 / cd_user :71 / cd_vxlan :73; loads :104/:116/:118; 39-extern census re-measured `grep -c 'extern const BaseApi' = 39`. Rust ladder RESIDENT: codec_api.rs STATIC_CODEC_EXTERN_NAMES [&str;34] "cd_llc" :117 / "cd_user" :129 / "cd_vxlan" :131 — NEVER re-touched (row ADDs real TUs only, the 18i-quoted rule NEXT.md :470-472).
Table arms: hidden-BUILDING_SO face x3 (18j census rides): cd_llc :190-:193, cd_vxlan :124-:127, cd_user :158-:161 (`SO_PUBLIC ... snort_plugins[]` NO-`#else`-less shape; static arm IS the harness face).
Records face: llc mod_ctor :156 mod_dtor :159 TRUE (BaseCodecModule LlcModule, llc_rules :35-:39 2 rows + term, RuleMap rows reuse rule_count); vxlan mod pair nullptr; user mod pair nullptr,:147/:148 EXPLICIT comments `nullptr,  // mod_ctor` — asymmetry census 1/0/0 (contrast daq3 trio uniform 1/1/1 and miscip pair 0/0/0 — the FACE-A probe MEASURED it, §8).
Ground DEAD-define face (llc "dead-code? measure"): ETH_DSAP_SNA :80 / ETH_SSAP_SNA :81 / ETH_DSAP_STP :82 / ETH_SSAP_STP :83 / ETH_ORG_CODE_ETHR :87 / ETH_ORG_CODE_CDP :88 — grep use-sites = ONLY the #define lines (never referenced; the SNAP arms use literal 0 :117-:119 and ETH_DSAP_IP/ETH_SSAP_IP :84/:85 ARE used :105/:106/:139/:140). SIX dead defines transcribed cite-NEVER-land (the cd_gre dead-init discipline).

## §2 CENTRAL CHECK — vxlan tunnel_bypass HOOK seam (the 18f witness face) RETURN
cd_vxlan.cc:73-74 MEASURED: `if ( codec.conf->tunnel_bypass_enabled(TUNNEL_VXLAN) ) codec.tunnel_bypass = true;` — the HOOK, NOT a checksum peg (18h correction face: peg-vs-hook, pin the callee). tunnel_bypass FIELD lives in copy framework/codec.h:143 (RESIDENT, `bool tunnel_bypass = false`). Seam faces: decl main/snort_config.h:777, body main/snort_config.cc:1020-:1023 (`!((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(proto))`), SFDAQ::get_tunnel_bypass sfdaq.h:58 / sfdaq.cc:389-:391, SFDAQInstance::get_tunnel_bypass sfdaq_instance.cc:259. Masks snort_config.h:119-:128 sed-pinned: GTP 0x01 :119 / TEREDO 0x02 :120 / GRE 0x40 :125 / VXLAN 0x100 :127 / GENEVE 0x200 :128 — EXACTLY the 18f witness_18f.cc face (ea1f79f3 heredoc, TUNNEL_GRE 0x40 rode at 18g). WINNER FACT: tunnel_bypass U-census of row .o MEASURED llc 0 / vxlan 1 / user 0 -> witness_18f CARRIED, EXACTLY-ZERO new bypass witness (the 18f SnortConfig::tunnel_bypass_enabled body + tun_witness_set_mask already define it; nm witness_18f.o grep -c tunnel_bypass_enabled = 1 MEASURED). NO tunnel_decap/encap/tunnel_encap calls in ANY trio TU (grep 'decap\|encap' cd_vxlan.cc = 0 hits MEASURED) — the dport-4789 face is NOT here: it lives in cd_udp.cc (landed cd_udp.rs :123 VXLAN_U_PORT 4789 + :147 PROTOCOL_ID_VXLAN 0x0108 REUSE cites).

## §3 LANDING MAP — flat src/codecs/{cd_llc,cd_vxlan,cd_user}.rs (3 new rs)
FLAT call per 18c-onward pattern; mod.rs wiring ONLY outside them; framework/codec.rs + parse_conf.rs + codec_api.rs + codec_module.rs BYTE-UNTOUCHED. REUSE cites per name: cd_llc -> CodecSid DECODE_BAD_LLC_HEADER=131/DECODE_BAD_LLC_OTHER=132 ALREADY codec_module.rs :97-:98; ETHERNET_LLC protocol_id::ETHERNET_LLC 0x0107 framework/codec.rs :167-:169; codec_event PUB (18c); llc_rules 2 rows reuse rule_count. cd_vxlan -> PROTOCOL_ID_VXLAN 0x0108 + VXLAN_U_PORT 4789 RESIDENT cd_udp.rs :147/:123 (import row-scoped or dup-per-precedent cd_icmp6.rs:183/cd_icmp4_ip ruling — PLAN-0 decides, dup face recorded); NEW row-scoped PROTO_BIT__VXLAN 0x040000 (decode_data.h:105 — NOT landed anywhere, grep src/codecs = 0 MEASURED; src header lives src/framework/decode_data.h, the utils/ guess in scoping is FALSE) + ProtocolId::ETHERNET_802_3 0x0105 (protocol_ids.h:132; landed? framework/codec.rs carries ETHERNET_LLC — verify the 802_3 face at row time) + CODEC_NON_IP_TUNNEL 0x0200 (copy framework/codec.h:101). cd_user -> DLT_USER 230 + DAQ_USR_FLAG_{TO_SERVER 0x01,START_FLOW 0x02,END_FLOW 0x04} + DIOCTL_QUERY_USR_PCI 2048 (daqs/daq_user.h :30-:46 fresh cp) row-scoped w/ h: cites; SfIp set faces + DECODE_C2S/SOF/EOF row-scoped (decode_data.h, the 18h row-vocab precedent); SFDAQ ioctl/get_local_instance = WITNESS-MIRROR fns (the get_proto_name precedent — NEVER invent the sfdaq body Rust-side); the set_key hardcoded 192.168.1.1/12345 pin transcribed w/ FIXIT-L comment pin.

## §4 TWO-LINEAGE CENSUS (live NOW, MEASURED outside the harness) + trio zero-gate claim
tools/*/gate.txt = 25 files; 4826fc2233044a2d5429413faf0ae1af holders = 9; distinct md5s = 17; `git ls-files | grep -c gate\.txt$` = 1. UNDISTURBED BY DESIGN — misc3 ships ZERO gate artifacts (grep 0 x3 §0) -> 18th straight. Ritual heads stay: gre x2 GATE anchor (6751d1a8), fmod frozen echo (gate 4826fc22 + tail verbatim), vocab vectors=29, daq3 x2 chain-echo (fd1855e1/2fb9dc45), miscip donor rebuild for the copy tree (MISCIP_HARNESS_OK vectors=23 faceA=11).
Copy tree per-file (fresh-cp census vs donor miscip face MEASURED): donor post-strip = 105 files (find ! -name '*.o' — the 18j addendum face, daq.h end-of-build rm; graft copy/daq.h receipt lives tools/daq3_harness/copy/daq.h 33 L md5 73fdbc3983ca45246b554c46efdf1ad1 find-1 CONFIRMED — the REUSE copy, NEVER a second graft). Trio adds EXACTLY 3 fresh cps: daqs/daq_user.h 54 L (head :18-:54 sed read; DLT_USER 230 :30) + packet_io/sfdaq.h 72 L + packet_io/sfdaq_instance.h 105 L (both include <daq_common.h> :25 = graft rides) + 3 row TUs = 105+6 = **111 MEASURED find-count in scratch**. Residency: framework/codec.h + codec_module.h + snort_config.h + text_log.h + active.h = find-1 in donor copy (all MEASURED); daqs/daq_user.h + sfdaq pair = find-0 -> the ONLY fresh cps; llc/vxlan/user headers = 0 faces (§1). E4 flipped walls REHEARSED scratch (receipts §6): drop each of the 3 fresh cps -> cd_user MUST die (rc 1 x3 MEASURED: 'daqs/daq_user.h: No such file...'); drop codecs/codec_module.h -> ONLY cd_llc dies (rc 1/0/0 MEASURED); drop packet_io/active.h -> ONLY cd_vxlan dies (rc 0/1/0 MEASURED); graft-only route (extended daq_common.h, NO cps) -> cd_user DIES at cd_user.cc:26 (fatal daqs/daq_user.h) = fresh-cp load-bearing PROVEN.

## §5 RISKS
R1 GRAFT FACE CHANGE = the row's one landmine: <daq_common.h> must EXTEND the fmod 16 L graft face for the pair headers: DAQ_IoctlCmd (sfdaq_instance.h:79 ioctl arg), DAQ_Config_h/DAQ_Instance_h/DAQ_RecvStatus/DAQ_Stats_t/DAQ_Verdict (sfdaq pair decls :44/:52/:68 + instance :45/:52/:93), DAQ_SUCCESS, and the **DAQ_Msg_h const flip**: donor face `typedef void* DAQ_Msg_h` fails cd_user.cc:101 aggregate-init `{ raw.daq_msg, nullptr }` (codec.h:59 `const struct _daq_msg*`) — g++ rc 1 "invalid conversion from const void* to DAQ_Msg_h" MEASURED; `typedef const void* DAQ_Msg_h` fixes user (rc 0) AND keeps daq3 trio TUs green (cd_udp/icmp4/icmp6 -fsyntax-only rc 0 x3 under graft-v2 WITH daq.h cp-verified) — BUT frozen harnesses are NEVER edited: graft-v2 lives ONLY in misc3's build.sh heredoc (copy/ is gitignored; every build re-materializes its own tree) — per-link isolation, the 18a inverted-landmine corollary.
R2 trio-split-vs-ALL-3: 498 L total is the cheapest misc landing; llc+vxlan are fully donor-resident (ZERO fresh cps between them); user drags the whole sfdaq/daq face. Alternatives: (a) ALL-3 one sweep (498 L, one graft-v2, one witness pair — RECOMMENDED, the misc tail CLOSES codecs/misc at 18k); (b) llc+vxlan only (331 L) banks user's daq face — pointless, the graft rides free after THIS row's build; (c) user only — NEVER split the census face, one row = one misc tail (the small4-4/"small four" naming precedent).
R3 llc dead code (§1: SIX unused defines) — transcribe cite-never-land; no rule risk.
R4 witness landmine ZERO: trio names cd_llc/cd_vxlan/cd_user grep-count = 0 in ALL harness stubs/witness files (grep -rn across tools/*/witness*.cc tools/*/stubs*.cc MEASURED 0) — vocab witness_stubs.cc stub table census stays 4 (cd_ipv4/ipv6/tcp :11-:13 + cd_hopopts :14); NO retirement face (the big trio 790/733/839 row keeps the ONLY retirements, NEXT.md :455-:460).
R5 E4 artifact naming must NOT pre-load daq.h rm collision: miscip excluded trio-riding window face re-asserted every build (the 18j tripwire text).

## §6 BACKBONE SCRATCH PROOFS (all run; NO git ops; tree /opt/data/cache/scratch/row18k/)
-fsyntax-only trio rc0x + .o receipts: `g++ -std=c++17 -O0 -w -Icopy` copy tree = miscip donor VERBATIM (105, .o stripped) + 3 cps + 3 row TUs (111): cd_llc rc 0, cd_vxlan rc 0, cd_user rc 0 (after graft-v2; pre-flip rc 1 = R1 evidence, receipts E4_cd_user.txt x2 stages). -O2 -c rc 0 x3 (O0==O2 arm material).
nm_U census per row .o MEASURED: cd_llc 22 / cd_vxlan 10 / cd_user 13 U-lines; mangled UNION (sort -u) = 28; snort:: family 12/2/5. Donor CONTRAST (miscip pair): 18/10/union-22 — backbone census stays 8 real objs (backbone8.txt face = small4+daq3+miscip 8-pin: small4 vectors 462f0ff6/faceA 4755d48c, daq3 fd1855e1/2fb9dc45 + witness_daq e0166b02, witness_conf 4dd91018, witness_18f ea1f79f3, stubs_18d f4afd35f = 8 md5 lines) pinned to 8 for this row.
Table-face nm: `nm o2/cd_*.o | grep ' D .*cd_(llc|vxlan|user)'` = EXACTLY-1 each MEASURED (D cd_llc / D cd_vxlan / D cd_user).
WITNESS delta MEASURED EXACTLY +2: staged L1 (3 row .o + 7 OBJS + WIN 3 + probe.o, NO trio witness) died rc 1 at undefined-DISTINCT face = {SFDAQ::get_local_instance(), SFDAQInstance::ioctl(uint,void*,ulong)} — file L1_undefined_distinct.txt; +witness_trio.cc (TRACKED candidate, the 17d/18i SYNTHETIC precedent; get_local_instance -> nullptr arm + ioctl fills static DAQ_UsrHdr_t) -> link rc 0, 2 T-symbols. get_proto_name face: `nm -u o2/*.o | grep -c get_proto_name` = 0 — witness_miscip.cc (TRACKED 27 L c5b498ff... md5 c5b498ffa6beac768f34e25830c552a1 RE-SUMMED) is DONOR-INHERITED (re-linked untouched: co-link chain rc 0).
Dup-collision landmine grep: trio symbol names vs ALL frozen stubs = 0 (§5 R4); co-link of row .o trio + donor OBJS + WIN + witness_trio = rc 0 (E_link_clean.txt) = no multiple-definition face this row.

## §7 HARNESS PLAN — tools/misc3_harness EXACTLY 7 TRACKED files (miscip face clone)
PLAN.md / build.sh / probe.cc / probe_dec.cc / vectors.txt / vectors_faceA.txt + witness_trio.cc (the daq3/miscip 7-file face, tracked witness = the EXACTLY-2 SFDAQ witnesses). stageables -eq 7 guard; vectors seeded FIRST-RUN then drift-then-refuse; O0==O2 cmp arms BOTH faces; all-decimal hygiene; two-lineage census loop echoed (9/25/17); frozen-donor md5 pins re-asserted NEVER re-derived (8 backbone pins §6); .gitignore misc3 block copy/ o2/ probe probe_O2 *.o witness_conf.cc vectors_O0/O2 nm_U_* E4_* L1_* md5_pinned gate census files = check-ignore at seed; NO gate.txt.

## §8 DUAL-FACE PROBES (FACE-A LOAD walk MEASURED now, arms + cites)
FACE-A (already ran scratch, vectors_faceA_scratch.txt): `API llc: type=0 name=llc ctor=1 dtor=1 mod_ctor=1 mod_dtor=1 / API vxlan: ... mod_ctor=0 mod_dtor=0 / API user: ... mod_ctor=0 mod_dtor=0` — the mod-pair asymmetry 1/0/0 MEASURED through the tables (BaseApi* lesson: probe walks the table BaseApi* slot, ctor/dtor read off the CodecApi cast; the 18j hidden-table walk face). DEC arms ground-call-sites ONLY (no EV re-walk beyond llc pair): llc short<3 EV 131 + SNAP-too-short EV 132 (cc:99/:110 — 131/132 resident codec_module.rs, NEVER re-walked sids), SNAP-0-org happy arm lyr 10 next=proto() (cc:121-:123); vxlan len<8 false + flags!=0x08 false + bypass arm (tun_witness_set_mask 0x100 face -> tunnel_bypass TRUE/FALSE arms, masks cite §2) + lyr 8 / 0x040000 / next 0x0105 / NON_IP_TUNNEL; eval order: conf->tunnel_bypass BEFORE lyr/proto_bits sets (cc:73 before :76-:79). user: NO-instance nullptr arm (ground would SEGV; witness returns nullptr -> ground cc:101 chain-calls without null check = ground-dead-style honesty face: arm via synthetic non-null instance), ip_proto!=0 set_ip TCP/UDP pair (cc:62) + USER/FILE pkt_type split cc:114/:119 + set_flags trio C2S/SOF/EOF (cc:85/:88/:92) + lyr raw.len vs 0 cc:93/:96; dport 4789 NOT here (§2). NEVER pull codec_api: link census MEASURED nm -u probe.o probe_dec.o | grep -c load_codecs = 0.
Ev-order/eval-site cites: cd_llc.cc :105-:106 (dsap/ssap AND-pair first), cd_user.cc :103 (ioctl call inside if), probe R6 var-first discipline per 18h/18j codified pattern.

## PROVES LIST (scratch /opt/data/cache/scratch/row18k/)
md5/wc trio x3 (§1); ladder externs :59/:71/:73 + loads :104/:116/:118 + 39-census; masks sed :119-:128; tunnel body sed config.cc:1020-:1023; E4 walls: E4_cd_user.txt (pre-flip R1), E4_no{daq_user.h,sfdaq.h,sfdaq_instance.h}.txt rc 1 x3, nocodecmodule/noactive face, E4_nocps_cd_user.txt; L1_link_face.txt + L1_undefined_distinct.txt (2 real); E_link_clean.txt rc 0; nm_U_cd_{llc,vxlan,user}.txt (22/10/13, union 28); table D -eq 1 x3; graft-v2 daq-trio rc0 x3 (E4_flipv2_*.txt EMPTY); vectors_faceA_scratch.txt 3 lines; copy=111 post-strip find-count; daq.h REUSE copy md5 73fdbc39 find-1. NO git ops performed anywhere (snort3-rust status stayed 0-lines pre-write; this PLAN.md is the ONLY file under snort3-rust touched, untracked NOT added).

## LANDING RECEIPTS (post-build pass, MEASURED this session — NEVER git-added)
- **graft-v2 rc receipts (R1 landed)**: `E4_cd_user_v1.txt` re-runs EVERY build: the
  f683749c 16 L face + fresh cps → cd_user rc 1 at cc:101 "invalid conversion from
  'const void*' to 'DAQ_Msg_h'" (matches scratch R1_flip_repro verbatim); the v2
  heredoc (md fead00270dd5, 28 L) lands OVERLAY-in-place ONLY in this build.sh
  (copy/ gitignored, re-materialized each build; frozen harnesses NEVER edited —
  per-link isolation). Post-flip: misc trio rc0 x3 + daq3 ip trio GREEN-under-v2
  rc0 x3 (`E4_flipv2_cd_{udp,icmp4,icmp6}.txt` EMPTY x2 builds). `copy/daq.h` =
  the 33 L 73fdbc39 REUSE cp of daq3's tracked landing (find tools -name daq.h:
  2 mid-build → STRIPPED end-of-build → 1; NEVER a second graft authored).
- **witness +2 (tracked face landed)**: staged L1 (trio .o + OBJS + WIN + probe.o)
  dies rc1 at undefined-DISTINCT EXACTLY-2 = {SFDAQ::get_local_instance(),
  SFDAQInstance::ioctl(uint,void*,ulong)} — `L1_link_face.txt` undefined-face set
  diff-identical vs scratch L1 receipt; +witness_trio.cc (TRACKED 35 L md
  ef50cd2f) → link rc0, own-new ` T ` census EXACTLY-2 (the PLAN §6 +2 pin; the
  miscip 18j face was -eq 1 — NOT carried), zero-other-new via residue loop.
  get_proto_name U-census of row .o = 0 → witness_miscip (c5b498ff, 27 L) stays
  DONOR-INHERITED cite, NEVER linked here. tunnel_bypass U-census trio 0/1/0 →
  witness_18f (ea1f79f3) CARRIED exactly (1 def), EXACTLY zero new bypass symbols;
  the vxlan HOOK :73-:74 not a peg face pinned by sed + mask 256/0 dual vectors.
- **FRESH cps**: md5/wc 1d2e2b9c/54 (daqs/daq_user.h — GROUND path is $SRC/daqs/,
  NOT src/daqs/: the scoping src/-prefix face corrected by measurement),
  2e272d2d/72, 9497f394/105; heads sed-cited (:19/:20/:20 author lines — the sfdaq
  pair share the same author comment face). Trio headers ZERO (find-0 built-in).
- **counts**: copy tree mid-build 112 (= 105 miscip post-strip + daq.h REUSE + 3
  cps + 3 TUs) / POST-STRIP 111 = 105+3+3 MEASURED literal; nm per-TU U-census
  22/10/13, demangled union 28 (PLAN §6 VERIFIED), mangled union 33 (new recv);
  table ` D ` EXACTLY-1 x3; mod_ctor asymmetry 1/0/0 FACE-A pinned (llc 1 = the
  trio's ONLY real module, slots :179/:180; user EXPLICIT null comments :147/:148).
- **vectors**: 18 L DEC + 19 L FACE-A; md5 e75f7385779aa89c365dd2ce4a208b67 /
  fe1189c6c78139b8828c1a8071e3df28 (MEASURED first-run, drift-refuse pins landed);
  O0==O2 BYTE-IDENT x2 faces; FRESH x2 build logs BYTE-IDENT (receipts
  /opt/data/cache/scratch/row18kdocs/misc3_{A,B}.log), tail VERBATIM
  `MISC3_HARNESS_OK vectors=18 faceA=19 gates=0`. Ground-anchored value census
  PINS BOTH WAYS in-PYTHON: sids 131/132 (landed codec_module.rs :97-:98 NEVER
  re-walked — import face), PROTO_BIT__VXLAN 262144 ZERO landed face,
  ETHERNET_LLC 263 / VXLAN 264 / ETHERNET_802_3 261 / CDAPI ver 1900547 /
  ETHER_NEXT 4096 / NON_IP_TUNNEL 512 / C2S+SOF+EOF 512+1024+2048 / PktType
  USER 5 FILE 6 / TUNNEL_VXLAN mask256 / GID 116 / GETDLT user 230 (the trio's
  ONLY data-link registrant). set_key hardcoded face: observable prints sp
  12345/dp 54321 (ground literals cc:75/:76 ARE the observable — print OK); the
  192.168.1.1/2.2 addresses stay sed-CITES in build.sh (ground cc:72, NEVER
  land). FIXIT-L cite pinned cc:70.
- **E4 walls landed IN-TREE**: 3 fresh cps each alone → ONLY cd_user DIES
  (fatal-error first-line greps cc:26/:28/:29); codec_module.h → ONLY cd_llc
  dies (cc:24); active.h → ONLY cd_vxlan dies (cc:27); daq.h → the ip trio x3
  DIE (REUSE graft rides) + misc trio x3 SURVIVE (fresh face: cc:24 is
  <daq_common.h> NOT <daq.h> — the fresh-cp-vs-graft split the scratch
  E4_nocps face pre-proved); restored -c rc0 x3 stderr-0 EVERY build.
- **BACKBONE 8→10 pinned** (receipt `backbone10.txt`): + miscip vectors
  43b259ac / vectors_faceA e4c47bac / witness_miscip c5b498ff + witness_trio
  ef50cd2f (small4 x2, daq3 x2 + witness_daq, witness_conf 4dd91018 carried).
  FM15 frozen direct-md5 loop VERBATIM; gre gate.txt 6751d1a8 + fmod tail +
  vocab self-pin chain echoes re-run. TWO-lineage census: 9 holders / 25
  gate.txt / 17 distinct md5s / ls-files gate 1 — UNDISTURBED (this row ships
  ZERO gate material, 18th straight; STOP-flag tripwire armed NEGATIVE, all 3
  misc/test CppUTest files TEST_CASE 0 + trio-refs 0).
- **donor FRESH x2 receipts**: daq3 logs BYTE-IDENT (DAQ3_HARNESS_OK vectors=93
  faceA=13 gates=0) + miscip logs BYTE-IDENT (MISCIP_HARNESS_OK vectors=23
  faceA=11 gates=0) post-18k row (row18kdocs/daq3_{A,B}.log,
  miscip_18k{A,B}.log) — the daq3 landing daq.h stayed 73fdbc39 THROUGH the
  whole pass (its own build.sh :105 exclusion census green: misc3/copy/daq.h
  NEVER stays). git status after ALL builds: ` M .gitignore` + `?? tools/misc3_harness/`
  ONLY; index EMPTY; dirty-guard rowface regex = daq3 landed template, NO own-
  HEAD pin (ground rev-parse fe29cbe ONLY); stageables face = EXACTLY 7
  (--others face, 18i posture: untracked NOT added, NO commit this pass);
  check-ignore proof loop landed (copy/, o2/, probes, *.o, witness_conf.cc,
  E4_*/L1_*/nm_U_*, vectors NOT ignored both explicit NOT-proofs).
