# PLAN.md — ipheavy_harness (the codecs/ip HEAVIES row: cd_ipv4 790 / cd_ipv6 733 / cd_tcp 839 = 2,362 L, ONE row, trio)

RECON-MEASURED CONTRACT (scratch root /opt/data/cache/scratch/row20a, everything below
MEASURED THIS PASS by this recon, not carried from docs). Ground /opt/data/snort3-src
@ fe29cbe READ-ONLY. Donor = tools/mpls_harness copy tree (the 18o 130-file post-cp face,
122-file post-strip face; graft-v3 daq.h 0f7016a6 + graft-v2 daq_common.h fead0027 INHERITED).

## 0. THE PICK (measured cost face, trio-over-split verdict)

Land ALL THREE TUs in ONE row in tools/ipheavy_harness (name pre-hit 0 — re-measured
THIS pass: git ls-files + fs find for ip4_harness/ip6_harness/tcp_harness/ipheavy_harness
ALL = 0/0). Rationale MEASURED, not taste:

- THE LANDMINE IS THE TRIO: the vocab witness_stubs.cc :11-:13 defs ARE the trio. A
  solo row retires 1/3 and forces a stub-lineage refreeze per row (14 L -> 13 L -> 12 L
  faces each md5-pin-frozen). Trio = ONE atomic diff-0 retirement, the LAST in the chapter.
- SHARED FRESH CPS: parse_ip.h + sf_ipvar.h needed by ALL THREE. Solo sum = 2+3+6 = 11 cp
  ops; trio = 7 UNIQUE cps (4 ops saved, 2 riders ride once).
- SHARED GRAFT-EXTENSION #4 (the NEW finding, §2.3): daq.h/daq_dlt.h copy-local extension
  demanded by the trio (pdd l3/ipv4/tcp bits + NAPT src/dst_addr + family accessors +
  DLT_IPV4/DLT_IPV6). Solo rows pay it x2-x3; trio pays once, all three consumers ride.
- L1 RESIDUE: solo residue 4 (ipv6) + 11 (ipv4) + 8 (tcp) = 23 witness arms vs TRIO UNION
  = 13 distinct (with carried chain) / **10 needing own arms** (daq pair + get_network_policy
  close on the carried daq3 witness_daq.o). Witness material is SHARED, not additive.
- HEADLINE: 2,362 L is the chapter closer — row 18 face reads "Remaining: ip HEAVIES
  ... = 2,362 L" — trio row = **CODECS CHAPTER 100% CLOSED** face (mirrors the 18o
  link 6/6 chapter-close story). Size exceeds the proven 417-721 landing band; the
  mechanism COUNT stays moderate (7 cps all <=288 L, 1 graft ext, 1 retirement, 2-3
  witness files). Fallback if the orchestrator enforces a hard size cap: cd_ipv6 SOLO
  first (2 cps + residue 4 = closure-cheapest solo; then ipv4+tcp pair pays ext#4 once).

## 1. GROUND IDENTITY (wc -l + md5, re-measured THIS pass)

| file | wc | md5 |
|---|---|---|
| src/codecs/ip/cd_ipv4.cc | 790 | def01f1df71ab250896da1764f6c0f92 |
| src/codecs/ip/cd_ipv6.cc | 733 | 89267b1d6d4f583434af207a14f90f56 |
| src/codecs/ip/cd_tcp.cc  | 839 | 144c427504a13c58dc117bcf93f6a604 |
| sum | 2,362 | (docs row-18 face 2,362 MATCHES ground) |

build.sh MUST pin all three md5+wc (mpls law), plus the chapter ledger: row 18 measure
11,914 L / 48 files, non-test 11,289; this row carries the LAST 2,362 non-test L.

## 2. CLOSURE: EXACT fresh-cp list per file (vs mpls 130-file copy face)

### 2.1 RESIDENT (do NOT cp — all verified present in the donor):
config.h, daq.h(INHERITED face), daq_dlt.h(INHERITED), codecs/codec_module.h,
framework/codec.h, framework/base_api.h, log/log_text.h, log/text_log.h, log/messages.h,
main/snort_config.h, main/snort_types.h, protocols/ip.h, protocols/ipv4.h, protocols/ipv6.h,
protocols/tcp.h, protocols/packet.h(INHERITED but see 2.3c), sfip/sf_returns.h,
utils/util.h, utils/safec.h(42 L stock-shim, 18o), **codecs/ip/checksum.h ALREADY RESIDENT**
(the csum/udp era carried it — grep the donor face). flow/flow.h + 5 riders ARE resident
post-18o (the PRE-PAY rider face pays off HERE).
<stdrandom> rides the host libstdc++.

### 2.2 FRESH CPS (unique trio set = 7; per-file counts ipv6=2, ipv4=3, tcp=6):

| cp | wc | md5 | needed by |
|---|---|---|---|
| parser/parse_ip.h | 28 | b7a327967e1f6a5303de363b77d56611 | ipv4, ipv6, tcp |
| sfip/sf_ipvar.h | 116 | 90b4aa20110f66b690da1fa38cbfaae6 | ipv4, ipv6, tcp |
| protocols/ipv4_options.h | 150 | cc4f7b4ab7c966ae5b516789a32ae9f1 | ipv4 |
| protocols/tcp_options.h | 181 | 68f3fc3b024290ebbb928c7a217e2c47 | tcp |
| stream/stream.h | 288 | c6bf6b8deca24e2eea9273021b6338d3 | tcp |
| flow/prune_stats.h | 159 | 26f386d3e05de5fa2600ea92a7acd7fd | tcp (stream.h rider) |
| time/packet_time.h | 38 | 52b9273657d8fc7d96292f2476ded5c4 | tcp (stream.h rider) |

parse_ip.h = 28-L pure fwd+proto (sfip_var_from_string) — ZERO transitive payload.
sf_ipvar.h drags only <cstdint> + sfip/sf_returns.h (RESIDENT). prune_stats.h drags
framework/counts.h (RESIDENT). packet_time.h drags <sys/time.h> + snort_types.h (RESIDENT).
**protocols/ipv4_options.cc / tcp_options.cc are NOT in the donor and NOT cp'd** — the
iterator TYPES come from headers; the METHOD BODIES are link-time witnesses (§3).

### 2.3 GRAFT-EXTENSION #4 (NEW landmine class, MEASURED rc0 x3 receipts):
pre-ext syntax walls (syn_cd_*.txt): cd_ipv4 10 errors / cd_ipv6 5 / cd_tcp 2 (second is
the packet.h redefinition §2.3c). The trio DEMANDS, the graft lacks:
(a) copy/daq.h EXTENSION: pdd bits +l3_checksum +l3 +ipv4 +ipv6 +tcp (use-sites
    cd_ipv4.cc:137, cd_tcp.cc:159); +int32_t l3_offset (cd_ipv4.cc:140/143);
    DAQ_NAPTInfo_t +uint32_t src_addr/dst_addr (cd_ipv4.cc:250-251, cd_ipv6.cc:216-217)
    +uint8_t src_addr_family/dst_addr_family + the 2 inline accessors
    daq_napt_info_src_addr_family()/daq_napt_info_dst_addr_family() (the SAME call-sites;
    SYNTHETIC SDK face, NEVER ABI truth, row 20 re-cites real SDK).
(b) copy/daq_dlt.h EXTENSION: #define DLT_IPV4 228 + #define DLT_IPV6 229 (HELP strings
    via ADD_DLT framework/codec.h:52 + decode arms cd_ipv4.cc:152 / cd_ipv6.cc:123).
    228/229 = libpcap-master CITE face, pin as SYNTHETIC.
(c) copy/protocols/packet.h RE-POINT: flowz/flow_fwd.h -> flow/flow.h (flow.h landed at
    18o; the donor's flowz decoy class Flow REDEFINES vs real flow.h:170 — cd_tcp
    stream.h:34 -> packet.h:30 chain). MEASURED: re-point -> cd_tcp syntax rc0.
GRAFT-V3 LAW RE-ARMED: heredoc COPY-LOCAL ONLY; masters daq3 daq.h 73fdbc39 +
daq_common.h f683749c + INHERITED link4 face fead0027/0f7016a6 + the 18o ext2 9b603f8f
md5-asserted UNDISTURBED ladder HEAD AND TAIL. Post-ext rc0 x3 CONFIRMED (syn5_*.txt,
+fsyntax and -c both). E4 drop-walls per §7 of the harness contract.

## 3. WITNESS LANDMINE — REHEARSAL RECEIPTS (the 17y/18e pattern, done LIVE)

Carriers (grep -v /copy/, THIS pass): tools/vocab_harness/witness_stubs.cc (14 L, md5
9fad7e9d..., the :11 cd_ipv4 / :12 cd_ipv6 / :13 cd_tcp trio defs — THE pinned block)
and tools/ext_harness/stubs_18e.cc (14 L, md5 a700f777..., frozen-minus-hopopts, trio
still at :11-:13). .o carriers: vocab witness_stubs.o + o2/witness_stubs.o (4 tables),
ext stubs_vocab.o (4), ext stubs_18e.o + o2/stubs_18e.o (3). The MPLS-ERA chain
(stubs_18d.cc/o, witness_18f/conf/flow) carries NONE of the trio names — the 18o donor
chain is CLEAN, collisions arrive ONLY if a harness co-links the vocab/ext stub .o next
to a real cd_*.o.

NAIVE CO-LINK RECEIPT (scratch duplink2.txt): trio .o's + frozen vocab witness_stubs.o +
empty main -> rc1, **EXACTLY-3 'multiple definition of `cd_ipv4/cd_ipv6/cd_tcp'** (zero
other dups). (The ext .o pair would give the same 3 at generation-2 faces.)

RETIREMENT CONTRACT (own stubs_20a.cc = frozen vocab MINUS :11-:13 PLUS marker):
diff receipts MEASURED: drops = exactly the 3 extern-def lines; marker = 1 line
"// RETIRED at 20a: ... real tables ip/cd_ipv4.cc:785 / cd_ipv6.cc:728 / cd_tcp.cc:834
land them" (TRUE table cites re-sed THIS pass: cd_ipv4[] at :785, cd_ipv6[] at :728,
cd_tcp[] at :834 — NOT the :11-:13 stub lines). Post-retirement .o nm: surviving EXPORTED
stub table = **EXACTLY 1, cd_hopopts** (nm 'D cd_hopopts'; the static stub_ipv4/ipv6/tcp
BaseApi consts die with their block). Post-retirement co-link with real trio .o's:
**dup=0** (L1_postretire.txt; the 18 remaining undefineds = the §3.1 residue, closed by
witnesses — NOT by resurrecting stubs).

VECTORS FACE FLIP: vocab vectors.txt (29 L md5 5da70e82, + _O0/_O2 copies) and
ext vectors_faceII.txt lines 2-4 pin the LOAD face **cd_ipv4_stub / cd_ipv6_stub /
cd_tcp_stub** — those harnesses carry their OWN frozen witnesses and are NEVER touched
(law: retirement happens in the new harness's copy ONLY; vocab 9fad7e9d + ext a700f77e
md5-asserted UNDISTURBED head AND tail every build). THIS row's OWN vectors print the
REAL names: the probe prints plugins[0]->name, real BaseApi name = the NAME define ->
**LOAD ipv4 / LOAD ipv6 / LOAD tcp** (stub-table-name vs real-table-NAME flip; the Rust
face codec_api.rs:82-83 CD_IPV4_STUB/CD_IPV6_STUB/CD_TCP_STUB stub records FLIP to real
records at this row — the codec_api.rs:18-21/:44-56 stub doc comments carry a re-cite
churn face).

### 3.1 L1 WITNESS CENSUS (measured, trio link vs mpls REAL chain + carriers):
carried = copy REAL .o's (codec/ip/sf_ip/util_cstring/util/text_log/module) + witness_18f
+ witness_conf + stubs_18d + witness_flow: raw residue 13 distinct.
ADD the backbone-pinned daq carrier witness_daq.o (e0166b02, tools/daq3_harness — T
daq_msg_get_data/daq_msg_get_meta + get_network_policy): **residue = 10 distinct**:
1-3. sfip_var_from_string / sfvar_free / sfvar_ip_in (ground definer sfip/sf_ipvar.cc —
    NOT in donor, do NOT pull the .cc world)
4-5. snort::LogIpOptions(TextLog*, IP4Hdr*, ushort) [cd_ipv4] / LogTcpOptions [cd_tcp]
    (ground log_text.cc:100-ish; the LogEthAddrs witness stand-in precedent = mpls
    witness_conf :46 face — do NOT pull the Packet/appid world)
6. snort::Stream::get_held_pkt_seq(Flow*, uint32_t&) (ground stream/stream.cc:872 —
    stream CH19 territory, witness stands, NEVER invent a body)
7-10. IpOptionIterator ctor(IP4Hdr*, uchar)/begin/end + IteratorIter::operator* (ground
    protocols/ipv4_options.cc — header cp'd, .cc world NOT pulled)
Carrier census for these 7 names across ALL tracked harness .o (find ! -path copy):
**find-0** — all 10 need own arms. Per-file residue (own-file, carried+daq3 chain):
ipv4=11, ipv6=4, tcp=8 (L1_face_*.txt receipts). Plan: ONE own witness file pair
(witness_ipvars.cc = arms 1-3; witness_opts.cc = arms 4-10) in the miscip 27-L mirror
shape, both stageables. Per-file E4/L1 arms: every file ALONE shows its face (4/11/8) —
the trio-vs-solo E4 census ride build.sh.

BACKBONE: backbone10.txt stays EXACTLY 10 (own-new witnesses ride the harness dir, NOT
the census — the witness_flow 18o law). nm delta face: row .o's define EXACTLY-1
exported table each (D cd_ipv4 / D cd_ipv6 / D cd_tcp, TRUE-NAME, nm-measured; cd_tcp's
table unconditional, §4).

## 4. TABLE / NAME FACES + HIDDEN ARMS (all sed-pinned in build.sh)

TRUE-NAME face holds: table name == file base for all three (mpls law; NO 18m drift):
- cd_ipv4: ipv4_api :760; NAME/HELP_STR/HELP #define :47/:48/:49 (HELP = ADD_DLT ->
  vector HELP face "support for Internet protocol v4 (DLT 228)" — DLT number is the
  graft CITE, tripwire §6); table :782-789: #ifdef BUILDING_SO :782 / snort_plugins
  :783 / **cd_ipv4[] :785** (LIVE hidden-table arm). WORDS_BIGENDIAN :379-385 (msb
  loopback; host LE arm = measured arm, BE cite-only). **#if 0 DEAD BLOCK :210-217**
  (ip_len<len alert) — NEVER port live. Real tinit/tterm arms (ipv4_codec_tinit/tterm —
  the ONLY one of the three with non-nullper t-arms). mod_ctor :718 / mod_dtor :721 /
  ctor(Module*) :754 IGNORES Module (contrast mpls :347 config-threading — drift cite).
  codec_event calls 27; RuleMap ipv4_rules :69-92 21 sids.
- cd_ipv6: ipv6_api :703; NAME/HELP :37/:38/:39 ((DLT 229) HELP); table :725-730:
  BUILDING_SO :725 / **cd_ipv6[] :728**. NO WORDS_BIGENDIAN, NO #if 0. tinit/tterm
  nullptr :719-720. RuleMap ipv6_rules :44-80 26 sids; codec_event 22.
- cd_tcp: tcp_api :809; NAME/HELP :42/:43 (NO-ADD_DLT HELP asymmetry); table :831-838:
  the BUILDING_SO block is **COMMENTED OUT (//#ifdef :831, //SO_PUBLIC :832, //#else
  :833, //#endif :835) — cd_tcp[] :834 UNCONDITIONAL**. Grep-c 'BUILDING_SO' = 1 LIES
  (the hit is a comment): census MUST use `grep -c '^[[:space:]]*#ifdef BUILDING_SO'`
  (cd_ipv4/ipv6 = 1, cd_tcp = 0) + commented-face assert. WORDS_BIGENDIAN :45-51
  (naptha_seq 0x2a7b5c00/naptha_id 0x9d01 LE arm — seed-drift tripwire law rides).
  tinit/tterm nullptr :825-826. RuleMap tcp_rules :74-96 20 sids; codec_event 20.
CMakeLists cite: trio listed in add_library(ip_codecs OBJECT) :44-47 with the
"static due to fpdetect / only file to use some functions" comments; the
add_dynamic_module lines :31/32/37 are COMMENTED (ground CMakeLists static-build face).

### SID BANDS vs the resident EV face (q4 census, parsed from codec_module.h enum):
enum face: DECODE_BAD_MPLS=170 / DECODE_MPLS_LABEL_STACK=176 pins MEASURED.
- cd_ipv4 decodes 21 RuleMap sids: {1,2,3,4,5,6,404,405,407..414,425,428,430,444,448}
- cd_ipv6: 26 sids {270..283,291,292,295,296,429,453,456,458,461,475,476,477}
- cd_tcp: 20 sids {45,46,47,54..59,400,401,402,403,419,420,421,422,423,433,446}
ALL THREE **INSIDE-170-176 census = 0** — the 18o EV-34 band {170x2,171x2,172,173,174,
175x26,176} NEVER-lands in these files; these files' sids NEVER-land 170-176 either.
Resident vectors EV census: the whole tools/ vectors set emits ONLY EV 116 (x436) outside
mpls — the trio's low (1-6, 45-59) and high (400-477) bands are FRESH vector material,
NO landed NEVER-land grep breakage (re-measure the 4 predecessor mpls vectors greps at
landing; law: own-row band flip only).

## 5. GATE / TEST_CASE CENSUS (honest zero-gate face + the test-side candidate)

Trio bare-token census MEASURED: TEST_CASE=0 / TEST_GROUP=0 / UNIT_TEST=0 / CppUTest=0
for all three files -> **26th straight zero-gate face** (link4 era law).
src/codecs/ip/ test-side INVENTORY (contrast link find-0): test/checksum_test.cc 201 L,
CppUTest dialect (TEST_GROUP x3, TEST( x10, CHECK( x4 — 10 case face), test/CMakeLists.txt
add_cpputest(checksum_test) x1. Host CppUTest headers find = **0** (whole-host find run
THIS pass) -> COMPILE-BLOCKED (the 19a posture: "header-blocked honestly, NOT landed as
artifacts"). It tests codecs/ip/checksum.h — ALREADY PORTED (csum era) — NOT the heavy
TUs; the 18g Catch-shim alternative WOULD re-author a 10-case Catch twin: RECOMMEND
record-as-candidate, do NOT land (the row keeps its zero-gate face; the trio adds gate
material for neither CppUTest nor Catch without NEW authored shims). build.sh census:
assert test-dir EXISTS (the face vs link), add_cpputest count in src/codecs/ip/
CMakeLists = the measured face, test/CMakeLists = 1, and the trio's OWN gate artifacts
grep-0.

## 6. HARNESS CONTRACT (tools/ipheavy_harness, mpls/misc9 8-stageable shape + nested .gitignore)

Stageables (8): build.sh, PLAN.md (THIS file), vectors.txt, vectors_faceA.txt,
witness_ipvars.cc, witness_opts.cc, .gitignore (nested instrument), + (probe-stageable
decision at landing: probe_dec.cc merged or split — mpls 8-face keeps probes UNTRACKED;
pick mpls). vectors DEC + FACE-A per the family shape: DEC = decode-path vectors per
file (ipv4: invalid hlen/frag bits/loopback/options ladder; ipv6: ext-header ladder +
ISATAP + bad next-header; tcp: offset/options/XMAS/SYN-FIN/NAPTHA consts + the LE
naptha arm pin 0x2a7b5c00); FACE-A = the NAPT real-addr arm (napti ip_layer match ->
SfIp::set(daq family) + ip_api.update — the ext#4 member face) + DLT HELP face +
the LOAD ipv4/ipv6/tcp real-name face (the §3 flip) + the cd_tcp unconditional-table
face. Tripwires: (a) DLT 228/229 synthetic-cite (row-20 real-SDK re-cite NEVER silent);
(b) BUILDING_SO non-comment grep per §4; (c) next to vocab 9fad7e9d + ext a700f77e +
vectors 5da70e82 + daq masters + 9b603f8f + INHERITED faces md5-asserted UNDISTURBED
head AND tail; (d) NEXT.md pinned-string carry law: NEVER drop 573x5 / 580x3 / 588x4 /
597x3 read-assert faces; the NEXT.md cargo cite rides per mpls :102-106 shape.
Donor self-heal: clone mpls copy (122-file post-strip census) with DONOR-DEAD guard,
rm *.o, then the 7 cps cmp-verified, then ext#4 heredoc daq.h/daq_dlt.h (pin the NEW
copy faces' md5 at first-measured face x2 — they are this row's ext2-9b603f8f analog) +
packet.h re-point sed-assert (flowz-flow_fwd grep-0 post-repoint, flow/flow.h grep-1).
E4 walls (MEASURED shape): donorsrc -I src ONLY must die rc1 at the trio headers'
chained fatals (per-file head-1 face varies — cd_tcp first-fatal face = stream.h:33
main/policy.h? re-measure at landing, NEVER pre-assume); drop-walls: parse_ip drop ->
sfip_var_from_string decl wall; sf_ipvar drop -> fatal; ipv4_options drop -> cd_ipv4 fatal;
tcp_options drop -> cd_tcp :115+ fatal; stream.h drop -> fatal :35 BUT prune_stats/packet_time
walls are NESTED via stream.h (the 18o clock_defs rider face); daq.h-drop = SURVIVES arm
MUST INVERT at this row (pre-ext#4 the daq.h fields ARE consumed — the trio breaks on
daq.h drop; contrast 18o mpls SURVIVES — the honest inversion receipt); packet.h NOT
droppable (the ch18 chain all needs it). -DNDEBUG law rides (production arm).
Rust side (landing child): src/codecs/ip/cd_ipv4.rs / cd_ipv6.rs / cd_tcp.rs NEW, mod.rs
+3, codec_api.rs stub-record FLIP per §3; sid consts already RESIDENT in codec_module.rs
(grep census THIS pass: DECODE_NOT_IPV4_DGRAM/DECODE_TCP_DGRAM_LT_TCPHDR/DECODE_IPV6_MIN_TTL
etc. all present — ZERO new consts expected; re-census at landing).

## 7. NEXT-ROW RANKING AFTER THIS ONE (the ch19 P2 assessment)

RECOMMEND: ipheavy trio NOW (chapter close + last landmine + shared closure); FIRST
row after = **ch19 P2 framework/reload_survivor_subscriptions.cc SOLO 631 L** —
misc9 PLAN P2 face re-read THIS pass: 2 cps (impl.h 156 + flow/flow_data.h 122 at the
REAL flow/ path — ALREADY resident since 18o, the cp is a path-formality), residue
EXACTLY-3 (get_reload_id/WarningMessage/DataBus::_subscribe) ALL likely closed by the
mpls-era carried carriers (verify at landing), UNIT_TEST clock seam = the 17e
interposed-clock arm; gate material REAL (47-case rsubs_test) but CppUTest-blocked =
same honest posture as §5. Ranking MEASURED why HEAVIES-before-rsubs: the trio closes
chapter 18 (a chapter-completion ledger head the docs bank already carries), defuses
the LAST witness landmine in the whole port face, and rsubs' DataBus::_subscribe residue
sits on the data_bus world which NEVER churns between the two rows (no ordering risk
either way — order by headline + closure hygiene, not by risk). rsubs-vs-heavy SOLO
closure-cheapest comparison: rsubs 631 L / 2 formality-cps / 3 residue — CHEAPER than
cd_ipv4 solo; but NO chapter close, NO landmine retirement, and the trio split then
costs the x3 stub ceremony anyway. Pair rsubs+data_bus (631+233=864) REFUSED per the
>800 band law (misc9 PLAN face). P3 rss (719 + flow.h-era drag) and P4 tracer
(graft-v4 interplay — note: THIS row's ext#4 makes the tracer tenant face CHEAPER,
record the cite) stay behind P2. thread_config 920 L = same fallback posture.
</content>
## 8. LANDING drift notes (row 20a MEASURED pass — disk won over body prose)

- STUB-TRIO CITE: the vocab witness_stubs.cc trio EXTERN-DEF lines (the retire-
  ment diff cut face) are :11-:13 — the STATIC stub BaseApi consts stand at
  :7-:9 (body §3 ":11-:13 defs" reads as the externs; both faces sed-pinned
  build.sh HEAD). ext stubs_18e.cc carries the SAME :11-:13 extern face (:14
  is the 18e hopopts RETIRED marker — the SECOND retirement precedent).
- FROZEN LOAD-PIN FACES (both, NEVER touched): vocab vectors.txt :25-:27
  (5da70e82, + cd_hopopts_stub :28 survives + LOADS 5 :29) AND the SECOND pin
  ext vectors_faceII.txt :2-:4 (cdaa92df, 5 L) — faceII re-pinned EVERY build.
- STAGEABLE FACE = 9, NOT the §6 "8": the own-new witness is a DUO (witness_-
  ipvars.cc 22 L + witness_opts.cc 35 L) — the measured EXACTLY-10 residue
  maps 3+7 across the two files (miscip 27-L mirror shape x2). .gitignore in-
  strument + probes + 2 vectors + PLAN + build.sh = 9.
- RULES table-order faces MEASURED: ipv4 n=21 first=1 last=425; ipv6 n=26
  first=270 last=477; tcp n=20 first=45 last=403 (the §4 sid SETS ride; the
  table first/last ORDER face is what the vectors print).
- PER-FILE solo residue with the FULL carried chain (OBJS + daq3 + 18f +
  conf + 18d + stubs_20a + emptmain): cd_ipv4=8 / cd_ipv6=3 / cd_tcp=5
  (L1_face_*.txt) — the §3.1 11/4/8 face rode a leaner chain; trio-union own
  L1 without the DUO = EXACTLY-10 CONFIRMED.
- ext#4 first-seed banks (my row analogs of the 9b603f8f law): copy daq.h 51 L
  97bca757, daq_dlt.h 14 L e8a39bf3, packet.h re-pointed 1be562b2; pre-ext
  rc1 counts 10/5/2 §2.3 CONFIRMED exact (cd_tcp faces = flowz redefinition +
  pdd tcp bit).
- vectors: DEC 121 L 857b5a10 / FACE-A 44 L 63df50bc; O0==O2 BYTE-IDENT;
  tamper face PROVEN (one byte sp/dp flip -> drift-refuse rc1). NEVER-land
  honest pins: EV 419 ZERO (the :266 URG gate CLOSED under the [>dsize] arm —
  the §6 "tcp offset/options/URP" draft guess DISPROVED), EV 58 ZERO (18/[4]
  default-case lands EV 54 — TCPOLEN_TRAILER_CSUM 3: the [18,3] FIXED face
  returns early, NEVER reaching the tail), 459 EXACTLY-1 (I4E MF + ip_len-=
  hlen -> :358 !ip_len IS reachable — the § body's UNREACHABLE claim rides
  the I4E face correction).
- NAPT match faces print HOST-order v4 values: src 167837954 dst 184549121
  (10.1.1.2 / 10.255.255.1) on BOTH NAPT4 and NAPT6 (the get_ip4_value face).
- E4 walls trio-map MEASURED: parse_ip fatal cc:35/:32/:31, sf_ipvar :40/:33/
  :34, ipv4_options cc:38, tcp_options cc:33, stream cc:35, prune_stats +
  packet_time NESTED fatal stream.h:32/:35; packet.h drop = chained fatal via
  stream.h:34 (it is NOT a direct trio include); daq.h-drop KILLS all three
  (the §6 SURVIVALS->KILLS inversion CONFIRMED, cc:25 head face).
