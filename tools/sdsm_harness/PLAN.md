# sdsm_harness — row 23i PLAN (chapter-20 LAST item: THE sf-daq_static_modules DIALECT row)

## 0. The row (ground-pinned EVERY build)
- THE TEMPLATE ground: `src/packet_io/sfdaq_static_modules.h.in` EXACTLY 11 L
  md5 `3b8e3f07189fb0a99bc3a50aac87ac3f` @ fe29cbe — a cmake configure_file
  TEMPLATE (the `@DAQ_STATIC_MODULE_EXTERNS@` / `@DAQ_STATIC_MODULE_DATA_ARRAY@`
  token faces + the `static DAQ_Module_h static_daq_modules[] = { ... nullptr };`
  body). THE GENERATED PRODUCT NEVER exists on disk anywhere (find-0 arm,
  the ground read-only) and is NEVER invented.
- THE generator MECHANISM: `packet_io/CMakeLists.txt` :17-:27 (the
  `foreach (STATIC_MODULE_NAME IN LISTS DAQ_STATIC_MODULES)` + the :19/:20
  `string(APPEND ...)` accumulators + :22 `configure_file` + :26
  `set_source_files_properties(sfdaq.cc ... ENABLE_STATIC_DAQ)` + :27
  `include_directories(${CMAKE_CURRENT_BINARY_DIR})`) — every line VERBATIM
  sed-pinned by the build.sh (the runtime-concat forms keep THIS file
  joined-token-free). `ENABLE_STATIC_DAQ` rides EXACTLY-2 faces in the
  CMakeLists (:17 + :26).
- THE landing seam rides the LANDED 23a home (NEVER re-landed; 23a md5s
  pinned: sf-daq.cc 420 `7ac13aa1…` / .h 72 `2e272d2d…`): the
  `#ifdef ENABLE_STATIC_DAQ` posts EXACTLY-2 (cc :38-:40 include post +
  cc :69-:71 THE ONLY call-site `daq_load_static_modules(static_daq_modules);`
  — grep-1, AFTER the dirs[] ctor legs, BEFORE the :72 dynamic call), + the
  :19/:20 blob faces in the Rust mirror's `externs_blob`/`data_blob`.
- ZERO-gate row: pair `TEST_CASE` grep-0 x2; packet_io test CMake
  `add_cpputest` EXACTLY-2 (the two suites, NEITHER this dialect's); NO
  gate.txt EVER; the walked census STAYS 28/9/20/1; backbone STAYS 10.

## 1. THE replay legs (the honesty face IS the row)
- leg (a) template VERBATIM cp + cmp + md5 pin (source of truth).
- leg (b) THE cmake-expansion replay with THE ACTUAL tool (this box cmake
  3.31.6, `cmake -P exp.cmake` running the ground :18-:21 foreach VERBATIM)
  over a STATED synthetic LIST `pcap;nfq;dump` — the product is 17 L (the
  11 + 2 + 4 `@sub@`-trailing-newline face), the LIST-ORDER face pinned at
  :4 (`pcap` FIRST), the nullptr tail at :15; BYTE-deterministic proven by a
  DOUBLE replay cmp EVERY build; the EMPTY-list degenerate face = the
  11-L token-substitute-EMPTY face (the accumulator NEVER created). THE
  PRODUCT IS A SYMBOLIC SHAPE, NEVER a claim it is a real build's generated
  header (the DAQ_STATIC_MODULES LIST is the BUILD's choice) — DEVIATIONS 23i.
- leg (c) the probe compiles/links against the REAL SDK api bodies (5 .o,
  ZERO donors; the `-D ENABLE_STATIC_DAQ` + `-include` product posture =
  the cmake :26+:27 face) and the FACE-A shape ladder rides the REAL
  DAQ_ModuleAPI_t / DAQ_BaseAPI_t / DAQ_InstanceAPI_t faces (sizeof/offsetof/
  macros, NOTHING retyped).

## 2. THE absent-SDK-decl wall (E4 BOTH ways EVERY build)
`daq_load_static_modules` is DECLARED NOWHERE in the shipped
`api/daq_module_api.h` 165 L `1a617b3e…` (grep-0 arm) — the decl home is
`api/daq.h` :42 (`DAQ_Module_h *modules`) and the REAL body is
`api/daq_base.c` :237 (`const DAQ_ModuleAPI_t **modules`) — THE TYPE-DRIFT
face (the typedef closes the C++ face — DEC D5 proves the handoff NO cast).
The generated-shape TU WITHOUT the cited daq.h rider dies EXACTLY-1 'was not
declared'; WITH it (the -include posture = the cmake :27 include_shape + the
owner TU's own `#include <daq.h>` :28 sitting BEFORE the ifdef post :38) it
closes rc0 SILENT.

## 3. THE vectors faces (FIRST-RUN-SEED, NEVER typed)
DEC 7 L `D0..D6` (hashes = FNV-1a 64 of the runtime-built blobs — the
algorithm the probe measures, the bloblens 152,80) + FACE-A 4 L. THE
stderr law measured: call-1 registers SILENT (rc = 3 = the WALKED-COUNT the
ground post DISCARDS); re-calls fail LOUDLY x3+x3 (6 'Failed to register
static DAQ module.' marks = the EXISTS trio per re-call) and the table NEVER
doubles; the missing-dir leg prints EXACTLY-1 'Unable to open directory' and
returns SUCCESS (dynamic_err=0). O0==O2 BYTE-IDENT; tamper-proven; the D2
ORDER face flipped by a sed tamper (order=1 -> 0) refused.

## 4. Tokens / census
- own 'sd-sm' family find-0 PRE-HIT (the sdsm/static-daq/s-dialect families);
  the dir name NEVER typed joined (MN="sd""sm"); NEXT.md arms pin the joined
  own-token ZERO BOTH branches + SD_SM_DONE ZERO.
- the strict sf-daq holder faces (da-qio / dir-stor / sf-mod / sf-inst / ac-t
  pins) ride PINNED UNMOVED — the union-exclusion walked arm proves THIS row
  adds ZERO new joined holders (the build.sh/exp.cmake ride the ${SD} runtime
  forms; self-scan arm proves it).
- the misc9 landmine legs STAY; ZERO new allows/unsafe; the D6 blob hashes are
  RUNTIME-name-built (NEVER a frozen literal).

## 5. Honest landing note (banked in DEVIATIONS row 23i)
THE row child banked the Rust leg + harness + vectors and died at its LAST
step (the twin NEVER authored); the orchestrator cold-run diagnostic purged
the UNTRACKED probe .cc files mid-debug (a scratch-hygiene reflex — the
probe .cc files WERE stageables and the dir was NOT yet committed); the
probes were RE-AUTHORED faithful to the pinned arm faces and reproduced the
seeded vectors BYTE-IDENT — the drift-refuse law did its job. The row
landed under the takeover law; the incident ledger rides DEVIATIONS 23i.
