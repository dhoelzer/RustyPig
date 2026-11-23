# daqio_harness — row 23a PLAN (chapter-20 OPENER; plan-table row 20 packet_io/DAQ OPENED)

## 0. The row (ground-pinned EVERY build)
- `src/packet_io/sfdaq.cc` 420 L md5 `7ac13aa1f5013ead580f5b4f61c38368`
- `src/packet_io/sfdaq.h` 72 L md5 `2e272d2d68e40138946326df3c5cfc95`
- rider pair `src/packet_io/sfdaq_config.cc` 131 L md5 `881eb03852b372c32ea1efca5c872507`
- rider pair `src/packet_io/sfdaq_config.h` 85 L md5 `df8f1875e163d4a588d48195cfdbad4c`
- 708 L total; ground @ `fe29cbe7403acc0dd428065a69d8f29cc311c18e`.
- Row pick via the E4 wall ladder BOTH WAYS: sfdaq pair (420+72 + the pure-value
  config pair) beats trough (265+88, fnmatch + the NOT-landed helpers/directory
  seam = left-open provider) — sfdaq closes against the REAL SDK with a MEASURED
  39-face nm census; trough's Directory wall would ship an unmeasured provider.

## 1. THE REAL-SDK RE-CITE (plan-20 law; the graft law DIES HONESTLY here)
The real libdaq clone LANDED: `/opt/data/libdaq` @ `c8d4083` (HEAD re-verified
every build; READ-ONLY like snort3-src). Every synth graft face is EVIDENCE,
never ABI truth. THE MEASURED RE-CITE LEDGER (compile legs = ledger_probe.cc
x5 families; drift legs = build.sh greps):

| family | face | md5 | pkthdr | ts | addr_space | tenant | verdict names | note |
|---|---|---|---|---|---|---|---|---|
| masters | daq3 33 L daq.h + 16 L daq_common.h | 73fdbc39 / f683749c | 16 | 0 | 0 | 0 | PASS/DROP only | pre-evidence |
| graft-v2 | misc9 daq_common.h | fead0027 | 16 | 0 | 0 | 0 | PASS/DROP | flow.h:541 era |
| graft-v3 / ext#4 | ipheavy daq.h+daq_common.h+daq_dlt.h | 97bca757 / 9b603f8f / e8a39bf3 | 16 | 0 | 0 | 0 | PAUSE/WAITING/COUNT SYNTH (2 lines; REAL 0) | MAX==6 was HONEST |
| 22b pkth ext | tracer daq_common.h (COPY-LOCAL heredoc) | b99e44b9 | 24 | 0 | 1 (u16 SYNTH) | 1 | — | the 22b graft |
| **REAL SDK** | libdaq api/daq.h 178 / daq_common.h 728 / daq_dlt.h 1413 / daq_module_api.h 165 | 35294a17 / 28789a3d / 57208729 / 1a617b3e | **56** | **1** | **1 u32@44** | **1 u32@48** | PASS/BLOCK/REPLACE/WHITELIST/BLACKLIST/IGNORE MAX=6 | THE ABI truth |

Flag drift legs (measured): SIGNIFICANT_GROUPS 0x20 (master) vs 0x8000 (REAL);
IGNORE_VLAN 0x40 (20a ext#4 daq.h) vs 0x8 (REAL :117); address_space_id
uint16 (22b ext) vs uint32 (REAL :146); DAQ_COMMON_API_VERSION 0x30013 exists
ONLY in the REAL face (grep-0 in ALL 3 synth daq_common faces); DLT_RAW=12 /
DLT_IPV4=228 / DLT_IPV6=229 (the 20a synth pins RE-CONFIRMED REAL);
DAQ_VERSION_NUMERIC=50339072 = (3<<24|0<<16|29<<8|0) (the configure.ac m4 face
3.0.29.0 — the daq_version.h.in sed face, the CMake configure_file dialect).
E4 PRE-RECITE wall: ground sfdaq.cc vs the ext#4 graft trio = EXACTLY-86
error lines flipped-assert every build ('DAQ_Mode' does not name a type +
daq_load_dynamic_modules was not declared named faces). POST re-cite: the
copy tree's daq.h/daq_common.h/daq_dlt.h/daq_module_api.h + the generated
daq_version.h are the REAL faces + 5 REAL api .o (daq_base/daq_base_api/
daq_config/daq_instance_api_defaults/daq_mod_ops compiled FROM the READ-ONLY
SDK sources) -> SILENT rc0 + the probes RUN against the REAL daq_base.c
verdict/mode tables + the REAL register ladder. The frozen daq.h find-0
arms (daq3 :105, misc3 :160, miscip :133 etc) are FROZEN-era; the live face
= 9 foreign copy-tree daq.h + this row's REAL copy (the 20a retirement
precedent, drift RECORDED never silent).

## 2. Witness posture
- CARRIED `witness_conf.cc` = the link4 :429-:471 heredoc EXTRACTION, md5
  `4dd91018f8439d706ba666c6f18c9152` (NEVER doubled; closes get_conf +
  FatalError + the thread/stats residues).
- OWN-14 `witness_daqio.cc`: EXACTLY-3 message mirrors (messages.h :51
  ParseError / :56 LogMessage / :60 ErrorMessage — FatalError carry-owned) +
  EXACTLY-11 SFDAQInstance mirrors = the row-23b provider seam (the REAL
  sfdaq_instance.cc 436+105 lands NEXT row; mirrors NEVER invent it).
- sfdaq.o nm app-undef census = EXACTLY-39: 25 `daq_*` SDK names (ALL closed
  by the REAL api link) + 14 snort (9 SFDAQInstance + 4 messages +
  get_conf). sfdaq_config.o = EXACTLY-0 pulls (the pure-value half).
- E9 one-home flipped-assert: dup message twin co-link = EXACTLY-2
  multiple-definition receipts rc!=0.

## 3. Vectors
- DEC `vectors.txt` 18 L (T0..T11 ladder: config defaults/sentinels, the
  first-'=' kv split, overlay unconditional-timeout asymmetry, inputs[0]
  overflow, DAQ_DEFAULT="pcap", print_types sort+unpriv inversion+var-descs,
  init pool=batch*4/snaplen/timeout/totals, the mode map via REAL
  daq_module_config_get_mode, the cumulative daq_module_names join static,
  the conf run_flags ladder -> REAL daq_mode_string, the wrapper auto-pcap
  wall, THE verdict table re-cite, forwarding_packet REAL NOT_FORWARDING arm,
  inject AND-short-circuits, stats, term unload walk + REG_TEST-off,
  NO_UNPRIV can_run). FIRST-RUN-SEED, drift-refuse, tamper-proven,
  O0==O2 byte-ident.
- FACE-A `vectors_faceA.txt` 11 L: the REAL C-ABI truth the Rust port mirrors
  as consts (SIZES pkthdr=56..., OFFSETS as=44 tn=48, ENUM, VERSIONS,
  MODESTRINGS, the register ladder via daq_find_module absence — the reject
  speeches ride a 7-line honest stderr leg, VERDICTS, DLT, TYPES, PKTFLAGS,
  the get_conf seam).
- ZERO-gate: the 4 ground files grep-0 suites; test/CMakeLists.txt
  add_cpputest EXACTLY-2 riders (sfdaq_counters/active_packet_trace — NEVER
  this row's files); CppUTest host find-0 BLOCKED; census STAYS 26/9/18/1.

## 4. Name law
`daqio` pre-hits EXACTLY-1 file (misc3 witness_trio.cc 'daqioctl' substring;
pinned); `daqio_harness` rides ZERO foreign build.sh; NEXT.md STATE-AWARE 0
pre-landing -> 1 docs-banked. The bare `sfdaq` token rides misc3/mpls/
misc3-parity (3 files FROZEN, never count-pinned). misc9 :461 landmine stays
find-0 by NAMING. Stageables EXACTLY-9 (the 22b 8-face + ledger_probe.cc);
ZERO gate material -> ZERO runner TU. `daqio_harness` must ride NEXT.md
EXACTLY-1 post-commit (the docs bank carries the cite line).
