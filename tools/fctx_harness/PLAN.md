# fctx_harness PLAN — row 17r: the HEAVY FileContext half (file_lib.cc:825–1362)

RECON-measured against `/opt/data/snort3-src` @ HEAD of snort3-rust `a06aa4b`
(row 17q landed: 406 tests / 48 suites / 0 FAILED, clippy 0).
This file is the RECON→HARNESS→PORT contract. Every number below was measured
this recon (grep/awk/link runs), not estimated.

## 1. Scope definition

Heavy half = the FileContext methods the 17q split left behind, plus its two
partner methods that sit below :825 in the file but belong to the same ladder
(the 17q fflows PLAN §7 heavy list + NEXT.md:81–107 + KNOWN DEVIATIONS.md:1338–1341
pinned-panics rule: bodies + the file_flows.cc:473/:486/:531 call sites land
in the SAME commit — semantics never split across rows).

## 2. Method inventory (measured, with cites)

13 FileContext defs live inside span :825–1362 (file_lib.cc 1624 lines; span =
538 lines incl. inter-block comments), + 2 partner methods outside the span:

| method | C span | LOC | Rust today (file_lib.rs line) |
|---|---|---|---|
| `process` (position form, MAIN ladder) | :825–984 | 160 | `unimplemented!` @ :1809 (`process_pos`) |
| `process` (offset form → FileSegments) | :986–992 | 7 | `unimplemented!` @ :1795 (`process`) |
| `find_file_type_from_ips` | :1004–1055 | 52 | not declared (comment-only @ :717) |
| `process_file_type` | :1057–1063 | 7 | not declared |
| `process_file_signature_sha256` (EVP ladder) | :1065–1167 | 103 | not declared |
| `process_file_capture` | :1169–1187 | 19 | not declared |
| `stop_file_capture` | :1189–1193 | 5 | DONE 17q @ :1349 |
| `stop_file_capture_unlocked` | :1195–1205 | 11 | done (folded into :1349 body) |
| `update_file_size` | :1207–1224 | 18 | DONE 17q @ :1745 |
| `print_file_data` (hexdump, FILE*) | :1226–1275 | 50 | NOT ported (comment @ :720 only) |
| `print_file_sha256` | :1280–1299 | 20 | ported string form @ :1640 |
| `print_file_name` (get_UTF8_fname caller) | :1301–1344 | 44 | ported string form @ :1614 |
| `print` | :1346–1357 | 12 | ported @ :1659 |
| partner: `file_signature_lookup` | :686–699 | 14 | not declared (comment @ :717) |
| partner: `finish_signature_lookup` | :701–742 | 42 | not declared |

Body LOC total = 564 (15 methods). Sum of TRUE 17r unlocks (not-counting
already-ported 6): ~450 C++ LOC.

Support machinery the offset-`process` drags in (all REAL TUs already linked in
the donor, NONE ported to Rust): `FileSegments` = file_segment.{h,cc} 355+78,
methods `clear` :54 / `add` :71–189 (119!) / `insert_segment` :191–239 /
`get_file_position` :241–255 / `process_one` :257–264 (calls back
context->process position form — the recursion edge) / `process_all` :266–302 /
`process` :305–354; singly-linked FileSegment{offset, std::string* data,
next, prev}. circular_buffer.{h,cc} 173+62 and file_mempool.{h,cc} 303+84 are
FileCapture-side (file_capture.cc:55 `FileCapture::file_mempool` static) —
they gate live but are NOT unlocked by 17r bodies.

Slot unlocks (the struct placeholders 17q parked):
- `file_type_context: Option<()>` file_lib.rs:1158 — C `void*`, file_lib.h:231
- `file_signature_context: Option<()>` file_lib.rs:1159 — C EVP_MD_CTX*; the
  Drop arm file_lib.rs:1211–1213 (`EVP_MD_CTX_free (17r)` comment) goes live
- `file_segments: Option<()>` file_lib.rs:1164 → `Option<Box<FileSegments>>`;
  the Drop arm :1217 and `remove_segments` :1720–1723 then delete for real

## 3. Seam vs donor classification (measured witness delta = ZERO new symbols)

Harness = **fresh `tools/fctx_harness/` directory copied from the fflows donor**
(build.sh cp list :45 already carries file_lib.cc, file_segment, file_mempool,
circular_buffer, file_capture, profiler TU pair, real data_bus — and build.sh
:376–377 compiles + links `file_lib.cc` VERBATIM into today's probe, so EVERY
symbol the heavy half references already resolves in the donor link):
`fp_eval_service_group` stubs.cc:612 (armable counter getter
`fcache_fp_eval_calls` :611), `DetectionEngine::set_next_packet` stubs.cc:579
(+ `fcache_set_next_packet` :578), IpsContext witness shape with
`file_data/file_pos/file_type_process` (stubs.cc:267 header note), policy
witness `type_lookup`/`signature_lookup` with settable tv/sv stubs.cc:319–322,
`PacketTracer::is_active/log` :211, Profile via real profiler TU pair +
`TimeProfilerStats::enabled=false` stubs.cc:73 (profile dead, no vectors),
EVP via the node-headers/libcrypto.so.3 recipe (build.sh :39–40, NEXT.md:65).

Classification per subsystem:
- REAL in donor copy tree (ground truth for free): file_lib.cc, file_flows.cc,
  file_cache.cc, file_segment.cc, file_mempool.cc, circular_buffer.cc,
  file_capture.cc, utf (get_UTF8_fname's convert_character_encoding), hashes.
- WITNESS (stays stub, arm-only deltas): fp_eval_service_group (real detection
  engine unportable), DetectionEngine class, PacketTracer, NetworkPolicy,
  FileService statics, ThreadConfig, Profiler stats.
- PORT-SIDE seam substitution (C real TU, Rust trait seam): FileCapture stays
  `Box<dyn FileCaptureApi>` (file_lib.rs:168) — file_capture.cc (913 LOC, 4
  [file_capture] unit tests incl. an async-writer thread dance) is its OWN
  backlog row (NEXT.md:115); `process_file_capture` C :1169–1187 allocates
  `new FileCapture(min,max)` — Rust injects the seam and calls
  `process_buffer`, record the substitution in deviations.

## 4. Gate plan

file_lib.cc's ONLY embedded UNIT_TEST block is the [file_info] suite
(:1363–1624, 19 TEST_CASEs) — already gated in 17o's tools/filib_harness
(measured: filib gate.txt tail "All tests passed (334 assertions in 19 test
cases)"). **Zero Catch cases live in the :825–1362 span** → the heavy half's
ground truth is probe vectors only. Free gate riders (both RECON-VERIFIED by
linking them against the donor closure today):

1. **NEW [file_mempool] gate — 3 cases, VERIFIED RUNNABLE**: TEST_CASEs at
   file_mempool.cc:231 (`m_free detects double free`), :243 (`m_free double
   free does not duplicate queue entries`), :273 (`m_release … duplicate
   queue`); UT block :223–303; block's own `mark_block_in_use` plant
   `*(MagicType*)p = 0` at :225–229. Recipe used this recon:
   `g++ -DUNIT_TEST -c copy/file_api/file_mempool.cc -o file_mempool_ut.o`,
   link `catch_main.o + file_mempool_ut.o + stubs.o + <all copy objs EXCEPT
   copy/file_api/file_mempool.o (duplicate-symbol rule)> + libcrypto.so.3
   -lpthread` → **"All tests passed (27 assertions in 3 test cases)"**. The
   exclude-the-plain-.o rule is required (nm dup errors otherwise).
2. **Carry the fflows gate**: [file_flows] 8 cases / 22 assertions
   (fflows gate.txt md5 `e14626fc6f112a9786c7098e6b4df40c`) — recompiled
   `-DUNIT_TEST` in the NEW link (new-link rule; fflows' committed vectors
   stay untouched, retire rule).
3. **Carry the fcache gate expectations**: [file_cache] 7 cases / 42
   assertions (fcache gate.txt "All tests passed (42 assertions in 7 test
   cases)", vectors 278 lines md5 `b69db31078f6bf6be88eba7615378748`).
   Optional as a 3rd UT TU in the same gate binary; keep fcache's own gate.

Gate binary = all three UT TUs in one link (skill rule: each UT-compiled TU
excluded from the plain objs list). Pin case names/counts from grep, measure
assertions from the run.

## 5. Probe plan (probe.cc driver — the fflows probe cut BEFORE all this)

Fresh driver: construct FileContext through the real FileFlows path (donor's
FF_TEST_CONTEXT pattern), then drive the heavy ladder DIRECTLY — the fflas/
fcache witnesses above make every call live. Proposed blocks (vectors labels):
- **K** `process` position-form ladder: data_size<0 →true :831–832;
  trace_stream print arm :834–838 (print_file_data output INTO vectors —
  hexdump boundary cases len 7/8/9/17/18, isprint/isspace table edges);
  type+sig disabled :842–851; cached_verdict_lookup hit (J-style, counts
  file_cache_hits++ :856) / miss :863; type unknown → 4 config clears :871–882;
  type found + type_lookup verdict arms (STOP clears sig :909–910, apply_verdict
  :911–913, block/reject PT line :915–921); sig ladder :930–977 incl.
  DEPTH_FAIL verdict arms :953–975 (force_adv_log sandwich :971–973).
- **L** find_file_type_from_ips: depth truncation :1009–1015 (negative
  data_size return :1012–1013 — signed cast), de ctor :1018, p->context writes
  :1021–1026, swap/no-swap :1032–1043 (context==this skip), FP_EVAL witness
  line, finalize_file_type condition :1046–1047, conditional restore :1048–1054
  (re-entrant replaced-current check — the 17q swap/restore pair goes live here;
  pair already real in Rust at file_flows.rs:356–374).
- **M** sha256 EVP ladder (REAL libcrypto): all 4 positions × sig_state arms;
  known-answer digest inputs (uppercase print precedent), FLUSH copy-ex ladder
  :1093–1105/:1117–1129, END/FULL finalize :1133–1162, depth-fail :1070–1077.
  Quirk to pin + deviation: mixed allocators (snort_alloc :1096/:1120 vs
  `new uint8_t[]` :1139/:1155; snort_free :737 vs reset_sha's `delete[]`
  :362–366) — structurally excluded in Rust, recorded.
- **N** process_file_capture: `new FileCapture` (REAL TU in donor) +
  process_buffer state + stop-on-nonsuccess :1183–1184; this retires zero
  Rust witnesses (capture stays a Rust trait seam).
- **O** offset-`process` → FileSegments queue ladder: out-of-order offsets
  exercising add/insert_segment, the overlap-trim :310–323, head-ahead drop
  :326–333, backlog gate :345–348, process_all drain loop.
- **P** print_file_sha256 / print_file_name (UTF-16LE BOM + |XX| runs,
  DAQ-activated header suppression :1310/:1339) / print tail (file_type_name).
Determinism: donor fake clock (HrClock seam arming), fresh relative workspace
for any logged paths if they leak (skill rule), no pointer values in vectors
(md5 the result x2 clean rebuilds — and x3 before commit per NEXT ritual).

## 6. Rust unlock list (PORT contract — same commit retires all 3 flows panics)

1. `src/file_api/file_lib.rs` :1773–1811 — replace the whole "17r seam bodies"
   block: `process` (offset, C :986) and `process_pos` (C :825) get verbatim
   bodies.
2. New FileContext methods, declared + verbatim: `find_file_type_from_ips`,
   `process_file_type`, `process_file_signature_sha256`, `process_file_capture`,
   `file_signature_lookup`, `finish_signature_lookup`, `print_file_data`.
   `file_signature_lookup`'s `FileFlows::get_file_policy(flow)` reach (C :692) —
   thread the flows/policy handle via PacketView/env, deviation note.
3. `src/file_api/file_segment.rs` NEW module (mod.rs entry — grep-guard the
   exact module name): FileSegment node + FileSegments 7 methods verbatim.
4. `file_segments: Option<()>` (file_lib.rs:1164) → the real Box; Drop :1217
   and remove_segments :1720–1723 go live.
5. `file_signature_context: Option<()>` (:1159) → incremental SHA-256 context
   (crate has ZERO deps — hand-rolled SHA-256 with init/update/copy/final,
   doc-comment pinning EVP call mapping incl. copy_ex on FLUSH, tmp-null and
   copy!=1 failure arms never fire => recorded); Drop arm :1211–1213 live.
   `sha256` unified as one owned buffer (allocator-pair deviation §5-M).
6. `src/file_api/file_flows.rs` :1052/:1056/:1151 — the call sites ALREADY
   route through `cb.process`/`cb.process_pos` (17q wired the routing; only
   the callee panicked), so unlock = delete the 17r panic texts; update
   comments at :805/:1008/:1047–1048/:1144–1145.
7. `PacketView` (file_cache.rs:254–259) extend: file_data/file_pos/
   file_type_process/snort_protocol_id + proto_bits/PKT_ALLOW_MULTIPLE_DETECT
   (mirrors the IpsContext witness shape; C :1021–1026).
8. FileEnvLite: DetectionEngine seam (set_next_packet arm, GET_CURRENT_PACKET
   already at file_lib.rs:1035) + `fp_eval_service_group` callback seam.
9. user_file_data_mutex (recursive :1068/:1172/:1191): keep the 17p
   single-thread deviation; model the lock/unlock ORDER only where observable.
10. Test: `tests/fctx_parity_test.rs` — whole-transcript replay of
    vectors.txt (include_str!, grep-counted line assertions) + `up_gate_*`
    translations of the new 3 [file_mempool] cases + carried fflows cases.
    Suite gate: full `cargo test` zero FAILED + `clippy --all-targets` 0.

## 7. Harness mechanics (copy the fflows donor; skill step 15)

`cp -r tools/fflows_harness tools/fctx_harness`, then: probe TU list swaps its
driving target to file_lib.cc MINUS its #ifdef UNIT_TEST block (excision via
`s.find('#ifdef UNIT_TEST')` guarded — file_lib.cc has the block at :1363 AND
early `#ifdef UNIT_TEST` fragments at :37/:54 — excise the :1363 one ONLY);
gate list = [file_flows UT, file_mempool UT] (+ optional file_cache UT), each
UT .o replacing its plain .o in the gate link. .gitignore block: mirror the
fflows pattern (copy/, probe, probe.o, gate, catch_main.o, stubs.o, vectors.txt
TRACKED, gate.txt TRACKED) — `git check-ignore` + `git show --stat` before add.

## 8. Risks flagged for HARNESS/PORT children

- Duplicate-symbol gate rule (measured this recon): UT TUs must not coexist in
  one link with their plain .o (linker error list otherwise).
- EVP ctx copy/ex failure arms are compile-visible dead branches — do NOT sed
  the original source to dodge them (dead-branch symbols still link).
- `isprint/isspace` locale edges in the hexdump/print arms: probe with byte
  arrays 0x00–0xFF, not literals; pin via vectors.
- update_file_size clears processed_bytes at END/FULL (:1217) — any sha
  ladder ordering the probe observes must be printed BEFORE/AFTER in C order.
- finish_signature_lookup's else-branch frees sha256 (the mixed-allocator UB
  site; C :736–739): probe pins the NULLING observationally, Rust models
  Option::take — deviation, never replicate the free.
- FileSegments::process_one recurses into context->process position-form →
  Rust needs `&mut` re-entry: model FileSegments holding a back-reference the
  same way the skill prescribes for C mutual-call chains (explicit &mut args
  through one driver, not a self-referential struct).

## 9. Session ritual (NEXT.md:135–138, verbatim order)

md5 stability x2 clean rebuilds (x3 pre-commit); `cargo test` ≥ 406 zero
FAILED + clippy 0; plan-row grep-guard then insert; deviations append
(grep-guard); NEXT.md refresh (row 17s scoping + stats line — wiki trio owed
at 17r landing per commit a06aa4b); commit+push code then docs.
