# Row 21b PLAN — chapter-19 P3 PROVIDER: framework/survivor_flow_data.cc 88 L = THE SURVIVOR-FLOW-DATA PIN PROVIDER (RECON, probe-only)

RECON-MEASURED CONTRACT (scratch root **/opt/data/cache/scratch/row21b/**, everything below MEASURED
THIS PASS by this recon, not carried). Ground /opt/data/snort3-src @ **fe29cbe** READ-ONLY. Rust @
**167cb3c == origin (127 commits re-counted)**; porcelain = ZERO tracked churn at measurement time
(sibling ` M NEXT.md` = 21a-docs churn tolerated, NEVER touched). Scratch = ABSOLUTE path only
(NEVER under repo); NO cargo run THIS pass (orchestrator budget law); NO harness build LIVE — the
row .o was compiled ONLY inside scratch trees.

**NAME PIN (orchestrator-PINNED, pre-hit 0 RE-VERIFIED THIS pass): `sfd_harness`.**
`grep -rc 'sfd_harness\|flowdata_harness' tools/ NEXT.md` = EMPTY (both faces);
`ls -d tools/sfd_harness` = find-0 BEFORE this file (THIS PLAN.md = first sfd face on disk).

## §0 GROUND IDENTITY (q1 — MY re-measure, EXACT vs the orchestrator pins)

| file | wc | md5 |
|---|---|---|
| src/framework/survivor_flow_data.cc | **88** | **4b1eedaf70469172153c22cd91b4a682** (pin EXACT) |

**HEADER FACE (q1, "sibling .h face YOURS" answer): there is NO survivor_flow_data.h.** The
SurvivorFlowData DECL lives in `framework/reload_survivor_subscriptions_impl.h` :138-:152 (md5
**b437ba1cff967338b48b1b354743d64a**, 156 L — the 21a LANDED row face, byte-ident re-measured THIS
pass; the cc quotes it DIRECT at :27). `find src/framework -iname '*survivor*'` = exactly 3:
reload_survivor_subscriptions.cc, _impl.h, survivor_flow_data.cc — the cc is the SOLO new face of
this row. Rust-side residency check: `reload_survivor_subscriptions.rs` carries the **decl-only doc
mirror** (rs :1358-:1368 block + :45-:52 module doc, cites 88L/4b1eedaf verbatim) = the provider the
rs CITES and waits for — cite-never-carry, NEVER re-port.

The cc's OWN shape (ground read THIS pass): static `SurvivorFlowData::flow_data_id = FlowData::
create_flow_data_id()` (static-init pull!), ctor (assert pin, push_back, add_ref), dtor (rem_ref +
`InspectorManager::thread_drain_pending_tterm_if_pending` per pin), `add_pin` idempotent via
`std::find`, and the private `Flow::pin_survivor_flow_data(Inspector&)` (flow.h :607 PRIVATE; consumer
= flow.h :364/:375 set_gadget/clear_gadget PUBLIC inlines; the idempotent-per-DISTINCT-inspector A->B->C
comment :71-:72). **GROUND assert census: 3 (build.sh pin — the 21a cc `^assert(`-0/`assert`-2 face flips
HERE: this cc has `assert(pin);` x2 + `assert(pin);` add_pin = 3).**

### q1 INCLUDE CLOSURE + EXACT fresh-cp list (MEASURED rc0 syntax AND .o on TWO donor trees)

cc includes (:23-:35): `config.h` + `reload_survivor_subscriptions_impl.h` (DIRECT :27) + `<algorithm>`
`<cassert>` + **3 project heads**: `flow/flow.h`, `framework/inspector.h`, `managers/inspector_manager.h`.

- **flow/flow.h is the BIG rider**: flow.h :39-:51 pulls `daq_common.h` + `detection/ips_context_chain.h`,
  `flow/deferred_trust.h`, `flow/flow_data.h`, `flow/flow_stash.h`, `framework/data_bus.h`,
  `framework/decode_data.h`, `framework/inspector.h`, `protocols/layer.h`, `sfip/sf_ip.h`,
  `target_based/snort_protocols.h`, `time/clock_defs.h` (clock_defs.h:23 `USE_TSC_CLOCK` guard means
  `time/tsc_clock.h` is NEVER pulled on the donor arm — measured via the clean compiles).
- **RECON-21a wall re-measured + RESOLVED**: `managers/inspector_manager.h` (139 L babb1997, includes
  framework/inspector.h + framework/module.h — BOTH resident everywhere) = **find-0 NEW in EVERY donor**
  (rsubs/mpls/ipheavy/misc9) → fresh cp. `flow/flow.h` = **RESIDENT in mpls + ipheavy copy trees at the
  637-L GROUND face** — flow.h **765663d466f59ac9af76344d4ba1de9b BYTE-IDENT to ground fe29cbe** (also
  deferred_trust.h 90 L e65076b8, flow_stash.h 182 L 0bde2734, detection/ips_context_chain.h 54 L
  53156e1e, time/clock_defs.h 73 L 29200557 — ALL byte-ident residents; the mpls-era pull of the flow
  closure EARNED its keep exactly as 21a §1 predicted). **rsubs_harness has NO flow/flow.h** (only
  flow/flow_data.h + flow/flow_key.h) → a raw rsubs clone DIES (`E4_noflowh.txt`: `fatal error:
  flow/flow.h: No such file`).
- **EXACT fresh cps on the MPLS donor (RECOMMENDED): 3 files** —
  `framework/survivor_flow_data.cc` (88, 4b1eedaf) → copy/framework/ ;
  `managers/inspector_manager.h` (139, babb19979eeb25e32dbadb5ca30c385f) → copy/managers/ ;
  `framework/reload_survivor_subscriptions_impl.h` (156, b437ba1c — byte-ident to the 21a-landed face;
  NOT resident in the mpls tree = fresh cp, cite the 21a home, NEVER re-derive).
  Mid-build **130 + 3 = 133 MEASURED** (mpls non-.o face RE-MEASURED 130 this pass; find -name '*.o'
  -delete after cp -a).
- **ipheavy donor ALT (measured): SAME 3 cps, SAME 140+3=143 face** — flow closure resident byte-ident
  there too. **rsubs donor REJECTED (measured)**: flow.h gap alone costs the SAME 3 cps PLUS a 4th
  (flow.h 637 + deferred_trust 90 + flow_stash 182 + ips_context_chain 54 + clock_defs 73 = 7 cp ops
  worst case) = strictly dominated. **misc9 donor REJECTED**: flow.h find-0 (21a receipt face
  syn_sfd_copy.txt holds at 167cb3c).
- **GRAFT-VERSION LAW (NEW FINDING, MEASURED — the one sharp edge)**: flow.h :541
  `DAQ_Verdict last_verdict = MAX_DAQ_VERDICT` needs the ENUM-EXTENDED daq_common.h. The **mpls-tree**
  daq_common.h is md5 **9b603f8f (34 L, MAX_DAQ_VERDICT=6 — the ext#4 face; the NEXT-line :27/:30 face
  in-file)** = LEGAL for flow.h (compiles rc0 AS-IS, zero graft cp!). The **rsubs-tree** daq_common.h is
  **fead0027 graft-v2 (28 L, PASS/DROP only)** → the rsubs clone additionally dies at
  `E4_daqwall_rsubsclone.txt` `flow.h:541: MAX_DAQ_VERDICT was not declared`. So the donor choice is
  flow-closure + graft-version double-forced: **mpls (or ipheavy) clone, NEVER rsubs/misc9.** Graft
  masters cited, NEVER re-authored (daq3 master 73fdbc39; the ext#4 daq_common 9b603f8f rides the mpls
  tree COPY-LOCAL per the :143 NEXT face).
- Chained-header residency audit done: everything flow.h/inspector_manager.h pulls is find-1 in the
  mpls tree EXCEPT the 3 cps; the mpls tree carries `copy/framework/api_options.h` INHERITED (the
  generated-header shim, load-bearing, §6 raw-arm wall).

## §1 q4 SUBROW DECISION — cc SOLO, header face = CITE (measured)

Row = **survivor_flow_data.cc 88 L SOLO + reload_survivor_subscriptions_impl.h as a CITED
already-landed header (NOT a fresh row stageable; still cp'd into copy/ for compile closure).**
- cc SOLO POSSIBLE (opposite of 21a's cc+impl.h atomicity): impl.h drop → cc DIES (`E4_noimpl_sfd.txt`
  `fatal error: reload_survivor_subscriptions_impl.h`), BUT impl.h is 21a-owned and ALREADY PORTED —
  nothing new to land. flow.h drop → cc DIES (`E4_noflowh.txt`) but flow.h = donor-resident header,
  never a row stageable. Restored rc0 EVERY build.
- 88 + 0 (new headers) = the SMALLEST framework row of the chapter band-wise; trio-risk NONE.
- Ground consumers of the provider face (cite-only, NEVER providers here): flow.h :364/:375 (the
  set_gadget/clear_gadget pin call-sites — flow.cc 525 L = its own unlanded row),
  src/flow/test/flow_stubs.h:82 + managers/test/get_inspector_stubs.h:199 + socks_negative_test.cc:169 +
  mitigator_context_reuse_test.cc:251 (the stub re-def faces = the upstream test-world's OWN mirrors).

## §2 q2 nm WITNESS CENSUS — PROVIDER face, EXACTLY-9 own-new arms (mirrorable x9, FOUND-0 x9 — honest)

`nm -C -u sfd.o` = **20 U-lines** (receipt `nm_U_sfd.txt`; O2 face = 2 L SMALLER: the vector
`__throw_bad_alloc`/`__throw_bad_array_new_length` pair vanishes at -O2 — U-set delta MEASURED, an
HONEST O0-vs-O2 census face). snort-family residue = **EXACTLY 9** (every other U = libc++abi):

| U symbol | provider status | mirror arm |
|---|---|---|
| FlowData::FlowData(unsigned) | FOUND-0 (flow_data.cc unlanded) | finspect/stubs.cc:750 precedent face |
| FlowData::~FlowData() | FOUND-0 | fcap/stubs.cc:581 precedent face |
| FlowData::create_flow_data_id() | FOUND-0 | `++flow_data_id` EXACT (ground flow_data.cc:139-:140); + `FlowData::flow_data_id = 0` DEFINITION mirror required (finspect :748 precedent) or link DIES (measured `undefined reference to flow_data_id`) |
| FlowDataStore::get / ::set | FOUND-0 | single-slot vector mirror (the file_api-era graft law) — the 21a-NEIGHBOR 10-rig ALREADY carries these bodies (grep: FlowData* Flow::get_flow_data mirrors in fcap :531, fcapi :542 … 15 harnesses carry `create_flow_data_id`; NEVER double with a rig the link set pulls) |
| Inspector::add_ref / rem_ref | FOUND-0 (inspector.cc row P?) | GROUND-BODY face `++ref_count[1+get_instance_id()]` (inspector.cc:126-:130) legal in-member; fcap :400 precedent |
| InspectorManager::is_pending_tterm / thread_drain_pending_tterm_if_pending | **FOUND-0 — THE NEW IMGR pair face** (grep across tools/*/witness*.cc + probes = 0; finspect PLAN :166 already earmarks `InspectorManager-row` turf) | bodies mirror ground inspector_manager.cc :324-:332 + :1276-:1282 with a fake pending set (armable set/pending knob) |
| typeinfo for FlowData | FOUND-0 | rides FlowData vtable mirror (link-resolved by the stub TU; measured closure) |

**PILOT MEASURED END-TO-END (the de-risk)**: `witness_sfd.cc` (~40 L scratch) + 21a-pattern scaffold
(Inspector ctor/dtor + the 3 non-inline virtuals in PROBE per rsubs probe.cc :47-:51/:65 —
`_impl.h`-visible name-drift face: Option/InspectionStatus NOT names in scope = the ctor-mirror route
beats virtuals-subclass route HERE) + mirrored Flow ctor/dtor/release_gadget (the PRIVATE
pin_survivor_flow_data is reached ONLY via PUBLIC set_gadget/clear_gadget inlines — a HORN the row's
probe MUST respect) + FlowDataStore::~FlowDataStore + FlowStash::reset accounting-drop mirrors
(flow_stash.cc/flow_data.cc rows NOT landed). **Link rc0 + run rc0** with ONLY witness_sfd.o + sfd_ut.o
(NOTHING of the backbone .o set needed for the probe face — the 6 REAL backbone OBs stay for the
L1-linkage leg). Run ladder (verbatim): T0 ctor refs=1 + id_nonzero=1 / T1 addpin-twice sum=2 /
T2 dtor sum=0 + drained=2 / **T3 pinned=0** refs_a=1 (set_gadget on a GADGET-LESS flow pins NOTHING —
survival fires ONLY at rebind) / T4 rebind sum=2 / T5 not-pending early-return sum=1
(`probe_sfd_run.txt`). **The 2-U L1-vs-20-U own-new delta face: sfd.o adds ZERO to the backbone-10 array
face (stays EXACTLY 10 VERBATIM) and grows the ROW witness face 21a +3 → 21b +9 (honest census, NOT
carried; NONE of the 21a trio — _subscribe/get_reload_id/WarningMessage — is pulled by this cc:
`nm_U_sfd.txt` grep0 for all 3).**
- **SEAM FLIP FACE (the q2 money question, stated honestly): the Rust-side DECL-CITE stays DECL-CITE
  even after this row lands.** The rs `SurvivorFlowData` documentation block (`rs :1358-:1368`) flips
  from "provider NOT landed, nm-0-pull law" to "provider = sfd_harness row, nm census = provider DEFINED
  in sfd_ut.o (4 T arms ctor x2/dtor x3/add_pin/pin_survivor + B flow_data_id + vtable/typeinfo V faces
  MEASURED `nm --defined-only`: ctor x2, dtor x3, add_pin, Flow::pin_survivor_flow_data, W
  get_flow_data_id, B flow_data_id). **ZERO Rust-type flip is FORCED this row**: the rs still has ZERO
  reachable arm touching it (21a §4 face UNDISTURBED), `DataBusSubscribeSeam` stays the 21a-owned seam
  (NOT closable by this row — different seam), and `policy_resolution_failures` stays
  inspector_manager-owned NEVER-invent (bodies confirmed THIS pass: the ONLY bump sites remain
  inspector_manager.cc :652/:681; sfd.cc NEVER touches rss_stats — grep0). The C-side seam closes in the
  sense that the provider .o EXISTS (a future flow.cc-row probe can link sfd_ut.o instead of the
  flow_stubs.h no-op face); the RUST seam face needs a flow-world rs home (flow/flow_data port rank)
  before any SurvivorFlowData Rust type materializes — rank-honest, NEVER invent.
- UNIT_TEST face: **grep-0 in the cc** (vs 21a cc-4/impl.h-1) — UT-arm sfd_ut.o U-set **IDENTICAL** to
  release sfd.o (diff EMPTY measured); the -DUNIT_TEST arm stays a compile-discipline echo ONLY.

## §3 q3 GATE CENSUS — ZERO-land posture CONFIRMED + a REAL suite-face note

- Pair gate tokens **TEST_CASE / TEST_GROUP / CppUTest grep = 0/0/0 on BOTH ground files** (cc 88 L +
  the cited _impl.h face). `#ifdef` census cc = **1 (HAVE_CONFIG_H x1 ONLY)** — the cleanest
  #ifdef face of the chapter (build.sh pin).
- **THE rider suite is REAL but NOT host-buildable**: `src/flow/test/survivor_flow_data_test.cc`
  **268 L, TEST_GROUP(survivor_flow_data) x1 + TEST( x4** (single_nonpending/second_distinct/
  same_inspector_twice — measured, md5 99fd7d6f2a780c605374a5650d0df7f1); the CMake rider rides
  `add_cpputest(survivor_flow_data_test SOURCES ../flow.cc ../flow_data.cc ../flow_stash.cc
  ../../framework/survivor_flow_data.cc flow_stubs.h ../../sfip/sf_ip.cc)` = the row TU RIDES ONE real
  suite (src/flow/test/CMakeLists.txt = **8 add_cpputest TOTAL INCLUDING this row's rider** — the ride
  face verified THIS pass; 21a rode 2, 19a zero). **CppUTest host-BLOCKED
  RE-MEASURED at THIS host: /usr/include/CppUTest ls-0, ldconfig grep-0, find /usr/lib /usr/local/lib
  /usr/include = 0** — dialect-blocked precedent (18j/18k/21a), NEVER faked, NEVER compiled. The real
  CppUTest rider face is a FLAG (like 21a's rides-2-suites face): if the toolchain ever ships CppUTest
  the row RE-PLANS loud.
- src/framework/test/ inventory RE-VERIFIED: data_bus_test / mp_data_bus_test /
  reload_survivor_subscriptions_test (3 add_cpputest, UNDISTURBED — NOTHING there subscribes TO this
  TU; the data_bus suites ride data_bus.cc, not survivor_flow_data.cc).
- Frozen lineage RE-MEASURED @167cb3c (NOT carried): **25 gate.txt / 9 holders of 4826fc22 / 17 distinct
  md5 / 1 tracked**; gre anchor 6751d1a8 intact. **THIS row adds ZERO gate faces → the 28th straight
  zero-gate row face available** (`test ! -e gate.txt` pin like 21a :275).

## §4 HIDDEN-FACE AUDIT (q5)

- `BUILDING_SO` / `snort_plugins` grep **0/0** (no BUILDING_SO arm, no dlopen table — framework-TU
  identity; the **NOLOAD precedent HOLDS**). No sid/codec tables, NO enum NAME-drift faces (this cc has
  ZERO enums — contrast the 21a RssPeg census).
- OBSERVABLE FACE-A shape: (1) the **static-init provider pull** face — `Flow::pin_survivor_flow_data`'s
  static `flow_data_id` init calls create_flow_data_id at load; `nm sfd.o DEFINED` census = ctor x2 T,
  dtor x3 T, add_pin T, Flow::pin_survivor_flow_data T, W get_flow_data_id, B flow_data_id, V
  vtable/typeinfo/typeinfo-name + the whole vector W family (receipt this pass). (2) the **idempotency
  ladder** face: add_pin-dup no-op + the A->B->C distinct-inspector comment (:71-:72) probe arms.
  (3) the **private-member reachability** face: pin_survivor_flow_data PRIVATE flow.h :607 → probe MUST
  ride set_gadget/clear_gadget PUBLIC inlines (:361-:380) — a probe-shape law, not a data face.
  (4) a subscription-shape probe riding 21a registry faces = NOT needed (NO data_bus symbol in sfd.o;
  U-set proves ZERO dbus pull) — the FACE-A probe stays a pure flow/inspector-scaffold shape.
- `assert` census 3 (ground); `grep daq` on the cc = **0** (the cc NEVER mentions daq — the graft wall
  rides flow.h ONLY; honest: this row's daq exposure = the inherited 9b603f8f face, NEVER the cc).

## §5 HARNESS CONTRACT (what the build.sh MUST pin — 21a rsubs_build.sh shape)

- Ground pins: cc 88/4b1eedaf + _impl.h 156/b437ba1c (cite home = 21a) + flow.h 637/765663d4
  + inspector_manager.h 139/babb1997 **cp-pins**; sed pins: cc :33 `unsigned SurvivorFlowData::flow_data_id
  = FlowData::create_flow_data_id();`, :69 `void Flow::pin_survivor_flow_data`, :27 the DIRECT impl.h
  quote; _impl.h :138 class decl; flow.h :541 MAX_DAQ_VERDICT (the graft-version landmine grep),
  :607 private decl; inspector_manager.cc :324/:1276 body-shape cites (witness signature law);
  flow_data.cc :139-:140 create-flow-data-id body (the EXACT ++ face); inspector.cc :126-:130
  add_ref/rem_ref body shape. assert-pin `grep -c assert == 3`. Dialect pins: TEST_CASE/TEST_GROUP/
  CppUTest grep-0 x2 files; UNIT_TEST grep-0 (the 21a flip-loud census INVERTS to a ZERO-pin here).
- Donor: **MPLS DONOR REUSE CLONE** (the NEVER-auto-heal law; self-heal guard checks
  copy/flow/flow.h + copy/config.h + copy/framework/api_options.h) + `find -name '*.o' -delete` after
  cp -a; mid **133 = 130 + 3** asserted EVERY build. ipheavy ALT (140 → 143) = the cross-donor
  invariance receipt leg (vectors BYTE-IDENT across both trees, 21a flow_probe precedent).
- Witness law: **witness_sfd.cc = the ONE home** for the +9 mirrors (NEVER double with probe scaffold —
  the 21a re-learned law rides; probe.cc carries the Inspector ctor/dtor + 3 mirror virtuals + NOTHING
  else; NEVER link a scaffold probe.o AND witness.o for the same symbols). Carried WIN trio stays
  (witness_18f ea1f79f3 frozen + witness_conf heredoc re-materialize from `$L4/build.sh` + stubs_18d
  f4afd35f) — the sfd .o pulls NONE of their symbols (U-set proof) but the OBJS link leg keeps the
  backbone shape consistent. **NEVER double the file_api-rig FlowData mirrors (fcapi stubs family) —
  the sfd link set includes NONE of those rigs; grep-pin `create_flow_data_id` definition count == 1
  across the row link inputs (the flow_data_id DEFINITION-mirror trap was MEASURED live this pass:
  forgetting it = link DIES).**
- Backbone10 STAYS EXACTLY 10 VERBATIM (fcache/daq3/miscip/misc3 faces re-read THIS pass from
  backbone10.txt; a +9 witness = a ROW face, NEVER an array face) + FM15-style frozen md5 census +
  wc-10 assert. Frozen echoes (re-measured THIS pass, byte-stable): rvecs **9e303761 (12 L)** /
  rfaceA **42aa06fb (9 L)** immediate lineage; mpls tail b4b660e4/3066fc33 + MPLS_LINK_DONE; ipheavy
  tail 857b5a10/63df50bc + IPHEAVY_DONE; gre 6751d1a8 + `All tests passed (1 assertion in 1 test case)`.
- VECTORS (SMALL row → SMALL face, measured honestly, NEVER inflate): **DEC ~9-10 L** = the
  pilot MEASURED run ladder (verbatim `probe_sfd_run.txt`): `T0 ctor_refs=1 id_nonzero=1` (ctor add_ref
  + static-init id allocated) / `T1 addpin_twice_sum=2 distinct=2` (dup add_pin = no-op) /
  `T2 dtor_sum=0 drained=2` (per-pin rem_ref + drain_if_pending x2) / `T3 pinned=0 refs_a=1` (THE
  semantic face: set_gadget on a GADGET-LESS flow pins NOTHING — survival fires ONLY at REBIND, flow.h
  :361-:366) / `T4 rebind_sum=2 gadget=b` (A->B rebind -> SFD(a) born, a survives) / `T5 cleared_sum=1`
  (not-pending early-return in pin; release_gadget still rem_refs). ALL-DECIMAL; R6 law (state-calls store-to-vars); O0==O2 run cmp PIN + **O0-vs-O2 U-set
  delta = 2 (the two vector throw U lines vanish) documented as a census face, NOT a vectors delta**;
  cross-donor byte-ident leg (mpls vs ipheavy trees). **FACE-A ~7-9 L**: head NOLOAD framework-TU +
  BUILDING_SO-grep-0-x2 + snort_plugins-grep-0-x2; defined-sym census lines (ctor2/dtor3/add_pin/
  pin_survivor = 7 T + 1 W + B); assert-count line (3); private-reach law line. FIRST-RUN-SEED →
  md5_pinned.txt, drift-refuse after. vectors total DEC ~10 L / FACE-A ~8 L — the 21a trio 12/9 stays
  honest to compare; THIS row is SMALLER (single mechanism, no tables/enums).
- E4 walls (all MEASURED THIS pass, receipts `E4_*_sfd.txt` in scratch): (1) raw arm `-I$SRC/src` ONLY
  → `framework/api_options.h: No such file` (the generated-header wall, base_api:32 chain); (2) rsubs
  clone + flow cps WITHOUT the 9b603f8f graft → flow.h:541 MAX_DAQ_VERDICT wall (the graft-version law);
  (3) impl.h drop → FATAL; (4) flow.h drop → FATAL; restored rc0 EVERY build. Codegen faces: -c rc0 +
  O0/O2/.UT all rc0 both donor trees (U-IDENTICAL cross-donor MEASURED).
- Stageables target **8 faces** (21a shape): PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt
  vectors_faceA.txt witness_sfd.cc + NESTED .gitignore (copy/ + .o + probe binaries ignored; root
  .gitignore NEVER touched; check-ignore proof face-by-face; dir fully ?? UNtracked until the landing
  commit). name-pin census: `ls -d tools/*survivor*_harness tools/flowdata_harness` = find-0 asserts +
  THIS dir = the ONLY new tools face.

## §6 LANDED-STATE NOTES (the flip face this row gives the registry)

- 21a's rs decl-cite (:1358-:1368) + module-doc (:45-:52) become a COMPLETED cite face (provider row
  exists); the harness-side 21a pin `nm rsubs.o | grep -c SurvivorFlowData == 0` (rsubs_build.sh :303)
  STAYS VALID (rsubs.o STILL pulls nothing — now provable POSITIVE: sfd_ut.o is its definer; suggest
  the 21b build.sh carries the MIRROR pin `nm sfd_ut.o --defined-only SurvivorFlowData ctor >= 1`).
- Queue honesty: remaining chapter-19 faces after 21b = inspector.cc 175 L / data_bus.cc 233 L
  (the rss consumer rows, P3'), thread_config.cc 920 L (14 TEST_CASEs, NOT zero-gate, ON-STALL-ONLY),
  inspector_manager.cc (the IMGR owner — THE provider of 21b's +2 witness pair at REAL scale, cite-only
  forever), flow.cc/flow_data.cc/flow_stash.cc (the 525/161/215 L flow trio whose stub mirrors THIS
  row's witness keeps — cite-only). NOTHING in this row pre-empts them.

## §7 SCRATCH RECEIPTS (row21b, 18 entries at PLAN time, probe-only, NO live harness build)

tree (rsubs clone 127-file face + 7 sfd cps = 134, flow.h WALL leg), tree_mpls (mpls clone 130 +
3 cps = 133), sfd.o / sfd_ut.o / sfd_mpls.o / sfd_O2.o, nm_U_sfd.txt (20 U), witness_sfd.cc/.o,
probe_sfd.cc/.o/_O2.o/_bin/_bin2, probe_sfd_run.txt + probe_sfd_run_O2.txt (O0==O2 run-ident),
E4_donorsrc_sfd.txt (api_options wall), E4_noimpl_sfd.txt, E4_noflowh.txt, E4_daqwall_rsubsclone.txt,
daq_common_mplsmd5.txt (9b603f8f graft identity receipt).
