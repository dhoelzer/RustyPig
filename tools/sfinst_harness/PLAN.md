# sfinst_harness — row 23b PLAN (the SEAM-CLOSE row; plan-table row 20 packet_io/DAQ pair #2)

## 0. The row (ground-pinned EVERY build)
- `src/packet_io/sfdaq_instance.cc` 436 L md5 `0b2a92f5b16344794714cfeda2cae8ed`
- `src/packet_io/sfdaq_instance.h` 105 L md5 `9497f39441174c4260d4db22e55740bf`
- DECL rider `src/packet_io/sfdaq_module.h` 89 L md5 `2d53ba758a9c5be47865523dedc84983`
  (fresh-cp; `struct DAQStats` :61 + `extern THREAD_LOCAL DAQStats daq_stats` :87
  OUTSIDE `namespace snort` — the mangled-name law: inside-ns mints
  `_ZN5snort9daq_statsE`, the .cc :433 reads the BARE global; the witness rides
  the global face; `expected_flows` DAQStats field :82)
- DECL rider `src/packet_io/sfdaq_config.h` 85 L md5 `df8f1875e163d4a588d48195cfdbad4c`
  + the REAL body `packet_io/sfdaq_config.cc` 131 L md5 `881eb03852b372c32ea1efca5c872507`
  (the 23a-LANDED pure-value half rides the LINK — the ctor/dtor/get_batch_size
  .cc :46 legs; the E4_cfg compile leg SILENT flipped-asserted)
- 436+105 = 541 L pair; ground @ `fe29cbe7403acc0dd428065a69d8f29cc311c18e`.
- Row pick via the E4 wall ladder BOTH WAYS at THIS row: the pair compiles
  BYTE-EXACT against the REAL SDK head-to-head; the trough sibling (265+88)
  hits its OWN wall = the NOT-landed `helpers/directory.h` seam call
  (fatal-error receipt `E4_trough.txt`, flipped-assert EVERY build: the wall
  MUST stay or the row re-picks).

## 1. THE REAL-SDK ride (the frozen 23a law; NEVER re-litigated, PIN-RECHECKED here)
`/opt/data/libdaq` @ `c8d4083` (HEAD re-verified every build; READ-ONLY):
api/daq.h 178 L md5 `35294a1773477a9579c8494cb1dadfea` + api/daq_common.h 728 L
md5 `28789a3dc10b84c974118c38700755b4` + daq_dlt.h 209 L md5
`57208729d55b02341367d7ff9c24b39d` + daq_module_api.h 165 L md5
`1a617b3edef11431c9244bee728baadc` + the sed-generated daq_version.h (the
configure.ac m4 face 3.0.29.0 pin re-ridden). THE 5 REAL api .o ride the link:
daq_base / daq_base_api / daq_config / daq_instance_api_defaults / daq_mod_ops
(compiled FROM the SDK sources, copy-local). The two copy-local static DAQ
modules: `inst` = FULL-API (the real legs) + `stub` = the REQUIRED-TRIO-ONLY
face exercising the REAL `resolve_instance_api` OPTIONAL-fn defaults
(api/daq_mod_ops.c:403-:445): caps 0 / start/stop SUCCESS / get_error NULL /
msg_finalize NOCTX / inject_relative NOCTX / interrupt NOCTX / get_stats
NOCTX / get_input_specs NOCTX / DLT_NULL.

## 2. E4 faces (measured receipts, flipped-asserted EVERY build)
- `E4_graft.txt` — the pair .cc vs the LEGACY 22b graft face (ipheavy copy-
  tree era daq headers incl the 152 L legacy daq_api.h): rc1, EXACTLY-119
  `error:` lines (the named faces `daq_instance_destroy`/`DAQ_CAPA_BLOCK`
  = 0-FOUND on the REAL face, ASCII-quote find-0; 110 curly-quote faces).
- `E4_real.txt` — the pair .cc vs the REAL copy face: SILENT rc0 (the law).
- `E4_cfg.txt` — the REAL config .cc vs the copy face: SILENT rc0.
- `E4_trough.txt` — the trough .cc vs the copy face: the directory-seam wall
  (row-pick arm).
- PRE-RECITE flipped-assert leg: no separate legacy header set exists for
  THIS pair beyond E4_graft (the ipheavy legacy trio IS the pre-recite face;
  the dead child's `E4_inst_pre.txt` leg was NEVER COMPLETED — the E4_graft
  leg at THIS row IS the pre-recite wall, re-measured; the honest partial is
  cited HERE, NEVER hidden).
- the pair .o app-undef face = EXACTLY-32 (22 = the REAL
  `daq_instance_*`/`daq_config_*` SDK dispatches — the seam-close proof: the
  calls resolve to the REAL api .o, ZERO mirrors).

## 3. E9 one-face co-link (the frozen quad law)
`e9_dup_twin.cc` (regenerated heredoc) mints `SFDAQInstance::init` +
`DAQ_Stats`-witness dupes ONLY; the link MUST die with ≥1 `multiple
definition` line (receipt `E9_dup.txt`). The OWN-3 mirrors in
witness_sfinst.cc = daq_stats (global face) + layer::get_vlan_layer + the
Packet ctor/dtor pair; the carried witness_conf family (link4_harness
4dd91018 extraction, md5-pinned FIRST, then the ONE cited noreturn rider —
see §5) NEVER doubles. The seam-CLOSE flipped arm: ZERO `SFDAQInstance::`
mirrors in the OWN witness (the 23a own-11 mirror law DIES BY DESIGN — the
REAL body rides the link from the pair .o).

## 4. Vectors (FIRST-RUN-SEED; the 17p law)
`vectors.txt` = the DEC 17 legs (probe_faceA.cc names: T0..T17 — the DEC
probe probe.cc legs): ctor faces (id+1 1-based law, batch 0->64, dlt -1),
init ladder (instantiate OK / validate ParseWarning rides the FALSE
log_verbose face HONESTLY — SnortConfig.cpp:2216 never inits the flag, the
witness copy rides it), the stub OPTIONAL-resolve defaults (caps 0,
was_started false, start TRUE the default face, stop the DLT leg), the
full-API legs (start -> pool 8/8 + the verbose pair NEVER fires, dlt
DLT_EN10MB=1, can_* 6-face from caps 0x1007c7), receive/finalize accounting
(pool_available walk, finalize null INVAL), inject/inject_relative,
interrupt TRUE, stats NOTSUP -> the log face + the daq_stats pointer,
modify_flow_opaque/set_packet_verdict_reason/set_packet_trace_data ioctl
legs + the tunnel-mask face, add_expected (the `as=44` key-offset proof,
`ef=1` then `ef=2` global walk, the vft0 land-mark = the daq_instance_ioctl
REAL dispatch), reload, dtor destroy counts.
`vectors_faceA.txt` = the C-ABI/gate faces: SIZES (key=56 cef=88 sfo=16
spvr=16 sptd=24 pool=16 stats=96 msg=112 modapi=216 instapi=288), OFFS
(the address_space_id field EXISTS @44 — cc :391 FIXIT-M NEVER fills it),
CAPA/sum, TUNNEL/ceiling, DIO/EFLOW, the REAL state walk (rinc=0,
INITIALIZED 1, STARTED 2, STOPPED 3, pool NOTSUP, dlt DLT_NULL),
NULLFACE (caps 0/state UNKNOWN/err NULL/NOCTX legs), FATALLEG
(the set_filter NOTSUP -> FatalError NEVER-returns face — §5).
`faceA_stderr.txt` pin: the 'Couldn't set DAQ instance (iface) BPF filter
to 'vlan 7': (-4)' two-line face (NEVER a vectors line — the DEC
SILENT-stderr law, `probe_dec_stderr.txt` ZERO-bytes flipped arm).

## 5. THE noreturn rider (the 23b honest correction of the carried witness)
Ground `log/messages.h:105` declares `FatalError` [[noreturn]]. The CARRIED
link4 witness body (md5 4dd91018, pinned BEFORE the rider) PRINTS and
RETURNS — returning from a noreturn-declared callee is UB: crash-proved at
this row — every faceA leg rides O0-identical through the pair :94
set_filter FatalError call, then -O2 = 5/5 DETERMINISTIC rc139 SIGSEGV
(the .cc's post-call epilogue legally deleted). The rider swaps ONLY that
one line IN PLACE (print the SAME face, `siglongjmp` the probe-armed site,
else `abort()` — the real-snort contract); the faceA probe ARMS the site
around `inst.init()`. The SAME control face at O0 and O2: init NEVER
continues, `was_started()` stays FALSE. Drift of the pre-rider UB face is
RECORDED here, NEVER silent.

## 6. Vectors drift-refuse + O0==O2 byte-identity
build.sh: md5 + wc pins, line-anchors, the tamper-then-refuse probe
(copy -> sed -> cmp MUST break -> die), the .vectors_pristine face; the
O2 link/`cmp` byte-identity arms BOTH pairs; the token/foreign/census arms
clone the 23a :158-:216 law (bare sd-token STATE-AWARE 3->4 at landing =
the OWN parity twin legit landing; foreign-23a-name census EXACTLY-1 = the
misc3 witness daq-prefixed-ioctl WORD face, pinned by the THIS-harness
grep-0 law; `sfinst` foreign face = own harness dir + own parity twin
EXCLUDED, find-0 elsewhere).

## 7. Cargo/clippy (measured at the row, pinned)
- `cargo test --offline`: NNNN tests green / 0 FAILED over 80 result-lines
  (row 23b adds the sfinst_parity_test twin lines); the 684x3 + 659x3 +
  23a-80-line history faces re-asserted by the parity twin's include_str!
  tripwires (NEVER writes NEXT.md faces itself — the 23a :752-:758 law).
- `cargo clippy --offline`: ZERO warnings, ZERO allows (this row ships
  NONE).
- census: the 23a backbone10 md5 lines NEVER move; the gate bank NEVER
  moves (this row ships ZERO gate artifacts).
