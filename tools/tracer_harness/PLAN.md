# Row 22b PLAN — chapter-19 LAST row: framework/tracer.cc 73 L + tracer.h 125 L = THE PT_TRACE TRACELOGGERPLUG / TRACE LOG-API PAIR (RECON + probe face, MEASURED)

RECON-MEASURED CONTRACT (scratch root **/opt/data/cache/scratch/tracer22b/**, everything below
MEASURED THIS PASS by this recon, not carried). Ground /opt/data/snort3-src @ **fe29cbe7403a**
READ-ONLY. Rust @ **b5fb776 == origin (133 commits re-counted)**; porcelain = this dir ONLY.
Scratch = ABSOLUTE path only (NEVER under repo).

**NAME PIN (orchestrator-PINNED, pre-hit faces RE-VERIFIED THIS pass): `tracer_harness`.**
`find tools -maxdepth 1 -iname '*tracer*'` = find-0 BEFORE this dir (measured); the token
`tracer_harness` = 0 hits in every `tools/*/build.sh` (measured); NEXT.md carries the token on
EXACTLY-1 line (the name-PIN law line :789 — the ONE tolerated cite face, pinned EXACTLY-1 in
build.sh). HAZARD face re-measured: the bare word `tracer` pre-hits **13** f*-family build.sh cp
lines (packet_io packet_tracer.h donor cargo — a name-CENSUS hazard, NEVER a collision; this
harness NEVER rides the token `packet_tracer`). Dodge arms held: rsubs globs, `*sfd*`/`*flowdata*`
sets, the tc find-arms (:126-:128 of tc build.sh = tc-token faces, untouched).

## §0 GROUND IDENTITY (re-measured DIRECT this pass — the law; EXACT vs the 22a-era bank)

| file | wc | md5 |
|---|---|---|
| src/framework/tracer.cc | **73** | **9ee6b2ee33c4c98144f6a575891d1679** (bank EXACT — no drift) |
| src/framework/tracer.h | **125** | **98d53205a5ddaff48ba5c304d0658931** (bank EXACT — no drift) |

Pair = 198 L (build-asserted). The cc rides `src/framework/CMakeLists.txt` :28 (`tracer.h`) + :53
(`tracer.cc`) VERBATIM (the sed-pinned face) — framework OBJECT lib, ZERO dedicated suite.

**THE row's SHAPE (ground read THIS pass)**: tracer.h = the **PT_TRACE plugin-API header**:
`TRACE_LOGAPI_VERSION ((BASE_API_VERSION << 16) | 2)` (:33), `TRACER_FLAG__RESERVED 0x0` (:35),
the abstract `TraceLoggerPlug` (:43-:110 — pure `log()` :49, name ctor :46, the set/get pairs
api/ntuple/timestamp, `set_thread_type(char)` P/C/O-default-O switch :79-:92 reading
STHREAD_TYPE_PACKET/MAIN from main/thread.h, NSDMI cold defaults :102/:106-:109), the two
typedefs `TraceLogNewFunc`/`TraceLogDelFunc` (:112-:113) and `struct TraceLogApi { BaseApi base;
unsigned flags; ctor; dtor; }` (:115-:121). tracer.cc = TWO methods: `print_ntuple` (:30-:61 —
ntuple/p/ip_api.is_valid() guard :32, SfIpString pair + ntop :41-:42, the TCP|UDP port-gate
:44-:48, the ss stream face :50-:51, **THE pkth reads :52/:54-:55 AS=address_space_id +
if(tenant_id) TN=**, the delimiter face :58) and `print_timestamp` (:63-:72 — timestamp guard,
`char ts[TIMEBUF_SIZE]; ts_print(nullptr, ts);` + ':' tail).

**THE DAQ WALL — MEASURED LIVE THIS PASS (NOT carried)**: direct `daq` grep on both = 0, but the
pkth fields ARE the wall: compiling the ground cc against the donor graft daq_common.h
(9b603f8f ext#4, three-field DAQ_PktHdr_t) DIES with EXACTLY-3 errors at :52 `no member named
'address_space_id'` + :54/:55 `'tenant_id'` (receipt E4_pkthwall face, flipped-assert EVERY
build). The honest pre-banked option taken: **harness-heredoc pkth-field EXTENSION arm** — the
build.sh python GRAFT appends `uint16_t address_space_id` + `uint32_t tenant_id` to the 3-field
struct COPY-LOCAL (md5 face 9b603f8f -> b99e44b9 measured this pass; the daq3 graft MASTERS
73fdbc39/f683749c md5-asserted NEVER cp'd NEVER promoted; SYNTHETIC, NEVER ABI truth — the
row-20 re-cite ledger absorbs this extension EXPLICITLY per NEXT.md :837-:840 and the new ledger
line this row adds). ZERO faked vector values: the vectors print REAL printf'd strings.

## §1 DONOR + COPY TREE (MEASURED)

DONOR = **ipheavy ext#4 tree** (140-file non-.o face re-counted THIS pass; the tc 22a donor
identity, daq.h 97bca757 + daq_common.h 9b603f8f + daq_dlt.h e8a39bf3). Self-heal clone FIRST
(`if [ ! -e $IP/copy/cd_ipv4.o ]; then bash $IP/build.sh; fi`), `cp -a` + `.o` purge, mid-build
census 140 + 4 fresh rows (tracer.cc, tracer.h — find-0 faces PROVEN below — + graft IN-PLACE)
= **142** after, asserted EVERY build. Fresh cp of **both row files** VERBATIM (cmp-proved,
NEVER sed). Carrier residents md5-pinned (byte-ident to ground fe29cbe where the law applies):
`utils/util_cstring.cc 9f8173ee` (the REAL SnortSnprintf provider — cmp-proved ground-ident
THIS pass), `sfip/sf_ip.cc a9505892` + `protocols/ip.cc ee76e12a` (cmp-proved ground-ident),
`sfip/sf_ip.h 7ad22ccf`, `protocols/packet.h` (the ext#4 RE-POINT face 1be562b2 lineage —
ground 790-L-era NEVER re-ridden; the graft face owns it), `protocols/layer.h 4f02062b`
(ground-ident), `main/thread.h 272021f4` (ground-ident), `framework/decode_data.h`,
`framework/base_api.h 999a3540`, `main/snort_types.h ac24606d`, `main/snort_config.h`,
`utils/util.h`, `protocols/packet_manager.h d6774515`, `config.h b5ad224e`. **NO tracer.h EVER
in the ipheavy copy tree** (find-0 face pinned pre-cp this pass — the copy trees WITH a stale
tracer.h are the packet_tracer-era f* trees, NEVER this donor).

**STALE-DONOR LAW APPLIED**: `find $C -iname 'tracer.h'` = 0 BEFORE the fresh cps (measured);
EVERY compile flips the md5 of the two row .o arms — tracer.o 9ee6b2ee face + tracer.h 98d53205
face asserted via the copy, NEVER a re-ridden face.

## §2 LINK FACE + ONE-HOME CENSUS (MEASURED — the sfd FOUND-0-face precedent grows)

Link = `probe(.o) + tracer.o + ip.o(REAL protocols/ip.cc) + sf_ip.o(REAL sfip/sf_ip.cc) +
util_cstring.o(REAL utils/util_cstring.cc) + witness_tracer.o`. The tracer.o U-census over the
graft (post-compile, this pass): non-lib snort residue = EXACTLY-2 — `SfIp::ntop(char*)` (closed
by the REAL sf_ip.o) + `ts_print` (the util.cc:140 REAL provider home — NOT linked, see the
witness law) — std::stringstream/stream faces otherwise ALL libstdc++.

**witness_tracer.cc = the OWN-3 carrier face (EXACTLY-3, the honest census)**:
1. `snort::snort_strdup` — util.h:119 decl; the REAL body rides a utils TU the donor NEVER
   compiled (grep0 face: sf_ip.cc :pulls it) -> own mirror body (a legal strdup mirror).
2. `snort::layer::get_inner_ip6_frag()` — layer.h:143; ip.cc:112 region pulls it (id()/off()/
   off_w_flags()); the REAL provider src/protocols/layer.cc NOT donor-resident; the pull is
   UNREACHABLE on the tracer ladder (the `IpApi::set(const uint8_t*)` raw path NEVER called) ->
   DECL-body mirror returns nullptr, NEVER invented behavior.
3. `snort::ts_print` — util.h:122 / util.cc:140-:197 REAL home CITED NOT linked: linking util.o
   drags `SnortConfig::get_conf()` (util.cc:154) whose static is NULL at probe time -> the
   wall-clock + null-config SEGV face (subagent-survey pinned). The witness MIRRORS the util.cc
   default-arm face (thiszone=0 / UTC off / year off / yyyymmdd=false -> the :192-:195
   "%02d/%02d-%02d:%02d:%02d.%06u" SnortSnprintf face) over a FIXED anchor timeval
   (1710406800,123 = 2024-03-14 09:00:00.000123Z) — the tracer.cc :69 `ts_print(nullptr, ts)`
   nullptr arm would otherwise gettimeofday the vectors -> honest witness determinism, NEVER
   fake vector values (the vectors stay printf'd).
**packet-h mirror face (probe TU, NOT the witness)**: `Packet::Packet(bool){}` +
`~Packet(){}` + `uint8_t PacketManager::max_layers = DEFAULT_LAYERMAX;` — the packet.cc ctor body
(44-:61 Active/Layer alloc face) NEVER reached by the tracer read-set; the mirror is the
minimum scaffolding the probe's field writes need; honest CITE-NEVER-CARRY of packet.cc.

ONE-HOME law proven EVERY build: `nm tracer.o` U-face has ZERO `get_conf`; the probe face links
ZERO `get_conf` (grep-0 arm); `ts_print` DEFINITION count across all link inputs == 1 (witness);
`SfIp::ntop` EXACTLY-1 real home (sf_ip.o). NO witness_conf ride (the tracer link NEVER pulls
SnortConfig — the honest SMALLER link face vs sfd/tc).

## §3 PROBES + VECTORS (FIRST-RUN-SEED law — NEVER TYPED)

probe.cc = the DEC ladder T0-T9 over the REAL tracer.o: T0 flag-off guards ("" x2), T1 v4 TCP
full (ports ride, AS+TN, proto_next 6), T2 UDP ports + 17, T3 ICMP-only -> ports STAY 0 (the cc
:44 gate face, sp/dp DIRTY on the packet), T4 tenant_id==0 -> NO `TN=`, `AS=0` STILL emits, T5
ip_api cold (IAT_NONE -> is_valid() false) -> "", T6 nullptr packet -> "", T7 v6 + the UINT16
65535 / UINT32 max ceiling faces, T8 timestamp-ON = the witness-anchored "03/14-09:00:00.000123:",
T9 the lifecycle map P/C/O (set_thread_type STHREAD_TYPE_PACKET/MAIN/'X'->default) + instance_id
7 + name roundtrip + ntuple flip-back -> "" + `get_api()==nullptr`. MEASURED 10 lines.
probe_faceA.cc = the FACE-A hearts (the 19a/21a framework-TU NOLOAD precedent — BUILDING_SO/
snort_plugins grep-0 x2 on BOTH ground files pinned; NO enum/table/sid census face — the pair
carries ZERO tables, the 21a table-contrast law): NOLOAD head; **APIV arithmetic face** =
logapi 1900546 + reserved 0 + PT_TRACE ordinal 10; **THE SIZES face** (the C ABI truth no Rust
mirror can state): `sizeof(BaseApi)=64` / `sizeof(TraceLogApi)=88` (the base_api.h :74 comment
"BaseApi must be the prefix (ie 1st member) of all plugin api" is OBSERVED: head-4 = type; the
padding face); **DEFMAP** the h-NSDMI cold map (api null / both flags false / 'O' / id 0);
NAME roundtrip; **APIStruct** = the typedef INSTANTIATION face (stub addresses fill ctor/dtor —
NEVER called, set-faces read back); SETAPI roundtrip (the non-owning api pointer); **ISOLATE**
(the NO-statics law: a's set_api NEVER rides b — the per-object private NSDMI face). FIRST-RUN
MEASURED 8 lines (1 head + 7 — the sfd-twin count; NOT 9, disk wins). GATE: ZERO — faceA grep pins the h has ZERO TEST faces, the
framework/test CMakeLists EXACTLY-3 add_cpputest with find-0 tracer ride (the misc9 face RE-
CONFIRMED live this pass). O0==O2 BYTE-IDENT both faces (measured scratch; asserted EVERY build).
Seed flow = rsubs/sfd/tc: no vectors.txt -> SEED PASS copies the O0 outputs; else drift-REFUSE.
Tamper-proven: DEC flip (`TN=42` -> removed) MUST break the drift arm, restore MUST re-match;
FACE-A twin flips the SIZES face.

## §4 GATE CENSUS (ZERO-gate row — face RE-MEASURED by walk, NEVER typed)

tracer.cc/h carry ZERO UNIT_TEST/TEST_CASE/TEST( (grep-0 x3 pins); src/framework/test/
CMakeLists.txt `add_cpputest` EXACTLY-3 (the rsubs face re-confirmed), tracer grep-0 there; the
rider/dialect cites only -> dialect-BLOCKED, NEVER faked. The gate census STAYS the measured
26 on-disk / 9 legacy 4826fc22 holders FROZEN / 18 md5 lineages / tracked-1 (gre 6751d1a8) —
DIR-WALK + md5 census run EVERY build (never inherited), `test ! -e $H/gate.txt` ships.
backbone10 + frozen lineages re-md5'd (sfd + rsubs vector faces); the seeded drift tokens
NEVER touched; NEXT.md read arms = the tc :649-:656 NEWEST template + the 650 x3 face + the
**sfd-rider census face** (tests/sfd_parity_test.rs HARD-ASSERTS gate=26 — the 62d6fac lesson:
this row MUST keep that 26 face TRUE, zero-gate keeps it satisfied, asserted here).

## §5 NAME-CENSUS + LANDMINE ARMS (measured THIS pass)

misc9 :461 landmine greps `ReloadSurvivor|reload_survivor|struct Tracer` over src/ — the Rust
naming keeps the `struct Tracer` leg find-0: names = **TraceLoggerPlug / TraceLogApi /
TRACE_LOGAPI_VERSION / TRACER_FLAG__RESERVED** (the C names verbatim; `struct TraceLogApi` does
NOT contain `struct Tracer` — grep-armed EVERY build); a bare `pub struct Tracer` would DIE —
NEVER used. Census: `tracer_harness` in every tools build.sh EXCEPT this file = 0 files; NEXT.md
token = EXACTLY-1 (the law line); the bare `tracer` pre-hit 13 f* build.sh file-faces RE-MEASURED
and pinned EXACTLY-13 (the packet_tracer.h cargo — census hazard documented, NEVER a collision,
NEVER edited); this build.sh NEVER writes the `packet_tracer` token (grep-0 arm on itself).
8 stageables MEASURED (the sfd/rsubs 8-face shape GROUND at the row: no runner TU — ZERO gate
material; NOT blind-inherited). The tc_harness + sfd + rsubs harnesses re-run GREEN against the
landed face (lineage heads; the tc :126-:128 tc-token arms NEVER see the tracer dir name).
