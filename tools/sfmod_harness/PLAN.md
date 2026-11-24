# sfmod_harness — row 23c: packet_io/sfdaq_module pair 298+89 @ fe29cbe

THE row-23c C harness (the ipheavy donor, 150 files; the row pair + the
fresh-cp DECL riders compile SILENT against the REAL libdaq SDK @ c8d4083).

## Wall faces measured AT the row before picking (E4-style, BOTH candidates)
- WALL A (CHOSEN): `packet_io/sfdaq_module.cc` 298 `0c42d293d1b7989d54b25eb493b7936b`
  + `.h` 89 `14c6c3676e184501d99c8dc39061d496` — ZERO in-TU TEST_CASE
  (measured 0) = the ZERO-gate face. Fresh-cp active.h (the donor ALREADY
  rides it BYTE-EXACT ce608579 — the cp OVERWRITE face) + trough.h.
  E4_graft (graft-header-only, no bodies): silent rc0. E4_real (REAL
  bodies: value.cc + module.cc + sfdaq_config.cc + sf_ip/util legs):
  silent rc0 — the static_assert :179 rides the REAL daq_common.h
  enum-constant face (MAX_DAQ_VERDICT enum-member :321, value 6).
  The 23b-row graft face (34 no-member faces on that donor) NEVER
  repeats on the ext#4 donor: the REAL SDK face closed it.
- WALL B (rank-LATER, honest): `helpers/directory.cc` 113 + `.h` 49
  compiles SILENT (E4B_dir rc0); `packet_io/trough.cc` 265 compiles
  SILENT ONLY when directory.h lands FIRST in the same tree (E4B_trough
  rc0 after the directory cps; without them dies the #include fatal).
  directory DISARMS the trough wall — but the trough pair owns NO new
  SDK-ledger face and the sfdaq_module pair rode the 23b NEXT.md rank
  line; A carries the static_assert :179 ledger + closes the sfdaq.h
  SFDAQ::get_stats/get_local_instance call faces that rode the 23b
  witness stand-ins. B stays the honest NEXT candidate.
- THE gate candidate (rank-LATER, NOT this row): the 739+166 tracer-gate
  row carries EXACTLY 10 in-TU TEST_CASEs (MEASURED; the docs' 12-case
  face is WRONG — corrected in the row report) and 4 heavy walls
  (ips_context/batched_logger/stream_log/active) — unmeasured-deep,
  NEVER this row.

## The one-home law (E9 three-leg flipped assert)
daq_stats DEFINITION rides the ROW BODY .o (cc :218) — the h :87 extern
rider. The e9_dup_twin (thread_local twin + ParseError + get_local_instance
dup) rejects at BOTH link legs with EXACTLY-3 'multiple definition' faces.
The Rust side REUSES the 23b `DaqStatsRecord`/`DAQStatsHolder` home in
src/packet_io/sfdaq_instance.rs — ZERO re-authored stats record/holder,
ZERO same-commit rider needed on the 23b home (the landed
`SFDAQInstance::get_stats` face already serves `SFDAQ::get_stats` — the
module's cc :249-:250 gate reads exactly what the Rust sfdaq_module rides).

## Trough face (the honest mirror)
trough.cc NOT landed: `Trough::file_count` rides a witness mirror DEFINITION
(mirror-side, never-bumped → pcaps stays 0) + get_next/clear_file_count
mirror DECLs. The REAL bump lives in trough.cc get_next behind the
empty-queue nullptr leg — record-only here, body stays witness-owned.

## Witness posture
witness_sfmod.cc: ParseError mirror (the :156-:160 capture leg), SFDAQ::
get_local_instance + get_stats provider stand-ins (a scripted DAQ_Stats_t
store feeds the prep_counts walk), Trough mirrors + the file_count
DEFINITION, and the link-pull inert LogMessage/ErrorMessage vtables
(util.o pulls; the 23b-row witness does NOT ride THIS link — ZERO
doubled faces; witnessed-names-NEVER-bodies law).
witness_conf.cc: the carried 4dd91018 EXTRACTION + the cited noreturn
fatal-jump/abort rider (the 23b UB law; the raw face NEVER edited).

## Vectors (FIRST-RUN-SEED, tamper-proven, O0==O2 byte-ident)
DEC 19L (T0-T9 parser/table legs + S0-S8 the stats ladder: the null-local
:250-:252 gate, the dump-TRUE prev-carry :286, the zero-delta :277, the
data-RESET absolute :265-:269, the SUBTRACT wrap 2**64-19 law, the :357
NOW-skip, the :228 reinterpret identity, the trough pcaps=0 honest face);
FACE-A 7L (the REAL C-ABI stats record: sizes/offsets/orderings + the
max_verdict=6 enum face + THEHOME rowbody=1 mirrors=0).
