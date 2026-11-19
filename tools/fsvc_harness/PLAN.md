# fsvc_harness PLAN — row 17y: file_api/file_service.{h,cc} (the FileService statics TU: enable-flag trio + max_file_depth ladder + the cache-clear posture + the init/close lifecycle over the REAL file_api closure; probe-vectors-only)

Donor: `tools/fpolicy_harness` (row 17x, freshest; stubs.cc 877 L, probe.cc
336 L, gate 22 cases / 114 assertions, vectors.txt 27 L md5
`b989a8d5cddaf0a2289f5528121ddf35`). NEXT.md:101-:127 is the row-17y
scoping pass; this PLAN re-measures everything it claims and adds the
REQUIRED scratch-compile residue classification (§0/§2).

Ground truth: `/opt/data/snort3-src` @ `fe29cbe` READ-ONLY.
Port repo: `/opt/data/snort3-rust` @ `693b61c` (row 17x landed).

Row TU size measured THIS recon: `wc -l` = **112 (.h) + 270 (.cc) = 382**
(NEXT.md:112 "112+270 = 382" confirmed). `grep -c 'TEST_CASE\|UNIT_TEST'`
= **0 / 0 on both files** (measured; rc=1 no-match). => ZERO grafts fire,
ZERO gate delta BY CONSTRUCTION, self-check pins per the 17v-17x pattern.

---

## 0. SCRATCH COMPILE + nm RESIDUE CLASSIFICATION (the backbone — REAL run, this recon)

Method identical to the 17w/17x recon recipe. Recipe (reproducible):

1. `cp -a tools/fpolicy_harness/copy/ -> scratch/copy` (the VERBATIM donor
   closure, 33 .o's + all headers), then `cp snort3-src/src/file_api/
   file_service.cc scratch/copy/file_api/` (the 17y cp delta — the .h was
   ALREADY cp'd, fpolicy build.sh:87).
2. Header-closure loop: compile `-fsyntax-only` against `-I$C` ONLY;
   missing headers are cp'd VERBATIM from `$SRC/src`. Measured **13
   iterations to SYNTAX CLEAN**. New header cp's beyond the donor set:
   `main.h` (cc:34 — zero-include declaration header, `main_packet_threads
   _fully_paused()` decl at src/main.h:56), `mime/file_mime_process.h`
   (cc:37 — drags `mime/file_mime_decode.h`, `mime/file_mime_form_data.h`,
   `mime/file_mime_log.h`, `mime/file_mime_paf.h`, `mime/decode_base.h`,
   `decompress/file_decomp.h`, `helpers/buffer_data.h`, `flow/flow_stash.h`
   transitively), `search_engines/search_tool.h` (cc:38 — drags
   `framework/mpse.h`, `search_engines/search_common.h`). ALL header-only:
   zero TU compiles, zero link contribution (search_tool use in file_service
   bodies = grep-0, matching NEXT.md:133-:136 "header-only FREE").
   Resident already: `log/log_stats.h` (cc:32, build.sh:110), `main/
   snort_config.h` (cc:35, :103), `managers/inspector_manager.h` (cc:36,
   :102), `utils/stats/snapshot.h` (cc:39, :96), and all five file_api
   includes cc:41-:44 (:87).
3. `$GXX -c file_service.cc -o file_service.o` — COMPILES VERBATIM (0
   grafts, 0 seds). `nm -u` = **47 U entries**.
4. Classification against donor objs `nm -g --defined-only` (33 objs +
   stubs.o):

| class | count | symbols |
|---|---|---|
| **REAL-OBJ** (resolved by an already-compiled donor TU) | 14 | `file_stats_init/_term`<=file_stats.o (cc:184/:187); `get_file_config`<=file_config.o (cc:123/:149/:216/:229); `FileCapture::init/exit`<=file_capture.o (cc:138/:180 — probe link resolves through file_capture_probe.o's copy per donor rule build.sh:706; gate through file_capture_ut.o :652); `FileFlows::get_file_flows`+`file_flow_data_id`+`get_current_file_context`<=file_flows.o (cc:63/:258/:263); `FileCache` ctor/dtor/`get_num_entries`/`set_block_timeout`/`set_lookup_timeout`/`clear`<=file_cache.o (cc:130-:133/:81/:113/:175) |
| **RESIDENT STUB** (witness body already in stubs.cc — KEEP) | 3 | `ReloadError` (cc:155/:160/:162 — stubs.cc:123, "WITNESS ReloadError" printf); `SnortConfig::get_conf` (cc:89/:142 — stubs.cc:55); `FlowData::create_flow_data_id` (indirect via `FileFlows::init` inlined at cc:63 — file_flows.h:62-:63; stubs.cc:753) |
| **NEW app** (needs a NEW witness or a new real cp) | 5 | `main_packet_threads_fully_paused` (cc:101), `MimeSession::init` (cc:121), `MimeSession::exit` (cc:179), `InspectorManager::get_inspector` (cc:68), `ProtocolReference::find` (cc:143/:167, `std::basic_string` members come along: cc:143's `find("file_id")` literal) |
| **NEW plumbing** (libstdc++/libc — auto-resolved by the system libs, ZERO witnesses) | 25 | 14 `std::__cxx11::basic_string` internals (the `FileCacheClearResult.report`/`Counter::name` copies at cc:83/:113 via stats inlines), `operator new/delete` (cc:130/:175), 4 `__throw_*`, `__cxa_atexit`/`__dso_handle`/`__gxx_personality_v0`/`_Unwind_Resume`/`strlen` |
| total | **47** | 14+3+5+25 |

5. **New-witness trial + FULL CLOSURE LINK (the proof)**. Scratch
   `stubs_17y.cc` = donor stubs.cc with the TWO retirements of §2
   (FileService block + `get_file_processed_size` body) + a 4-witness TU:
   ```
   bool main_packet_threads_fully_paused()            // armable int
   void MimeSession::init(); void MimeSession::exit() // print pair
   Inspector* InspectorManager::get_inspector(const char*, Module::Usage) // -> null or armed
   ```
   plus the ONE optional real cp `target_based/snort_protocols.cc`
   (ProtocolReference::find BODY at src/target_based/snort_protocols.cc:92
   — its own `nm -u` = 35 entries = 1 resident STUB (`SnortConfig::
   get_static_name`, stubs.cc:57) + 34 pure libstdc++/libc plumbing, 0 app
   NEW). Result: **LINK_OK** with ONLY `undefined reference to 'main'`
   before the main stub, and RC=0 on run. => the five NEW app entries
   close with EXACTLY FOUR new witness bodies + ZERO if snort_protocols.cc
   rides as a real cp (find resolves there). NOTE the inline trio
   `is_file_type_id_enabled/is_file_signature_enabled/
   is_file_capture_enabled` (h:85-:87) never enters the residue — they
   recompile into file_inspect.o/file_policy.o call sites reading the
   REAL statics straight out of file_service.o.
6. **GATE REPRODUCED AT THE 17y SHAPE (strong pre-flight)**: donor gate
   rules (4 `_ut.o` TUs in, their plain .o + probe out, build.sh:652), row
   .o added, witness block retired — gate runs green and
   `scratch gate17y.txt md5 = 4826fc2233044a2d5429413faf0ae1af` =
   **byte-identical to fpolicy gate.txt** (re-measured this recon; the
   "34x IMGR acquire -> null / 0 FileInspect" pins build.sh:688-:689 ride
   unchanged). The zero-regression claim for 17y is MEASURED, not argued.
7. `nm -C --defined-only file_service.o`: 510 defined symbols; **the row
   .o owns 17 T defs** (16 `FileService::*` methods + free
   `snort::get_file_processed_size`) + 6 data defs (5 B .bss statics + `D
   decode_conf`).
8. Size/enum pins for the vectors plan (scratch probe over the real
   headers): `sizeof(FileCacheClearReport)=16`,
   `sizeof(FileCacheClearStatus)=1`, `sizeof(FileCacheClearResult)=24`,
   `sizeof(DecodeConfig)=48`; enum values READY=0, MULTIPROCESS=1,
   UNAVAILABLE=2, NOT_INITIALIZED=3, PACKET_THREADS_BUSY=4 (h:47-:54).

Scratch tree: `/opt/data/cache/scratch/fsvc_recon/` (throwaway; harness/
build.sh must re-derive everything from fpolicy build.sh VERBATIM + the
deltas in §2).

---

## 1. Verbatim symbol inventory (all cites fe29cbe)

### file_service.h (112 L) — complete

- h:35-:37 forward decls `FileEnforcer` / `FileCache` / `FileConfig`
  (FileEnforcer is NEVER used by the .cc — cc grep-0; dead declaration).
- h:41-:45 `snort::stats` fwd block (`class Builder; struct Group;`).
- h:47-:54 `enum class FileCacheClearStatus : uint8_t` — READY=0,
  MULTIPROCESS, UNAVAILABLE, NOT_INITIALIZED, PACKET_THREADS_BUSY
  (values pinned §0.8).
- h:56-:62 `struct FileCacheClearResult { status = UNAVAILABLE;
  FileCacheClearReport report; }` (h:60 default-init note; 24 B measured).
- h:64 `class SO_PUBLIC FileService` — ALL-static:
  - h:68 `static void init()` ("must be called when snort restarts")
  - h:71 `static void post_init()` (after permissions dropped)
  - h:74 `static void verify_reload(const SnortConfig*)`
  - h:77 `static void close()` ("when snort exits")
  - h:79 / h:80 `thread_init()` / `thread_term()`
  - h:82-:84 `enable_file_type()` / `enable_file_signature()` /
    `enable_file_capture()`
  - h:85 `is_file_type_id_enabled()` INLINE `return file_type_id_enabled
    .load()`
  - h:86 `is_file_signature_enabled()` INLINE bool read
  - h:87 `is_file_capture_enabled()` INLINE bool read
  - h:88 `is_file_service_enabled()` (out-of-line)
  - h:89 `get_max_file_depth(FileConfig* = nullptr)` — default-arg arm
  - h:90 `set_max_file_depth(const SnortConfig*)`
  - h:91 `collect_cache_usage(stats::Builder&, stats::Group&)`
  - h:93-:95 `get_file_cache_clear_status()` (doc: status check MUST NOT
    modify the cache)
  - h:96 `clear_file_cache()`
  - h:98 `get_file_cache()` INLINE `return file_cache;`
  - h:99 `static DecodeConfig decode_conf;` (PUBLIC data)
  - h:102 private `reset()`
  - h:105-:109 private statics: `std::atomic<bool> file_type_id_enabled`,
    `bool file_signature_enabled`, `bool file_capture_enabled`,
    `bool file_processing_initiated`, `FileCache* file_cache`.
- FIXACC note: `file_service.h` ALREADY rides fpolicy FIXACC
  (build.sh:291 first entry; 2 `private:` at h:101/h:104 -> n>=1 assert
  safe; already flipped on the donor copy, matching stubs.cc:584-:589
  direct-static arms).

### file_service.cc (270 L) — complete (0 UNIT_TEST fragments, 0 TEST_CASEs; cppcheck-free)

Includes cc:30-:44 (see §0.2 for cp verdicts). Statics:
- cc:48 `std::atomic<bool> FileService::file_type_id_enabled(false)`
- cc:49 `bool file_signature_enabled = false`
- cc:50 `bool file_capture_enabled = false`
- cc:51 `bool file_processing_initiated = false` — **dead upstream**:
  grep `file_processing_initiated` over all src/ minus this TU = 0; it is
  ONLY ever re-set to false (never read). Port as a dead field + deviation
  note, do NOT wire it into any Rust logic.
- cc:53 `FileCache* file_cache = nullptr`
- cc:54 `DecodeConfig FileService::decode_conf` (the non-trivial-ctor
  static — see Risk R1)
- cc:56 `// FIXIT-L make these params reloadable`
- cc:57-:59 file-scope (internal, NO nm residue): `static int64_t
  max_files_cached`, `capture_memcap`, `capture_block_size` — the
  reload-comparison shadow copies.

Method bodies (all 16 + 1 free):
- cc:61-:64 `init()` -> `FileFlows::init()` ONLY (h-inline ->
  `FlowData::create_flow_data_id` at file_flows.h:62-:63; the counter
  witness stubs.cc:753 KEEPS).
- cc:66-:74 `reset()`: guard `if (InspectorManager::get_inspector
  ("file_inspect", Module::GLOBAL)) return;` (cc:68) then clears the 3
  enable statics (the `file_processing_initiated` static is NOT touched by
  reset — upstream fact, don't "fix" it).
- cc:76-:84 `collect_cache_usage(stats::Builder&, stats::Group&)`: null-
  cache early return (cc:78-:79); `entries > 0` gate (cc:82);
  `builder.counter(group, "File cache entries", (uint64_t)entries)`
  (cc:83) — `stats::Builder::counter` is the snapshot.h:125-:136 INLINE
  static (measured: ZERO stats symbols in the residue) + std::string
  copies = the plumbing cluster of §0.4.
- cc:86-:105 `get_file_cache_clear_status()`: `!sc` -> UNAVAILABLE
  (cc:89-:91); `sc->max_procs != 1 or sc->mp_dbus` -> MULTIPROCESS
  (cc:93-:94); `!file_cache` -> NOT_INITIALIZED (cc:96-:97); `!
  main_packet_threads_fully_paused()` -> PACKET_THREADS_BUSY (cc:101;
  def src/main.cc:325, iterates `pigs[].analyzer->is_fully_paused()` —
  analyzer monolith, NEVER pull the real body); else READY (cc:104).
- cc:107-:116 `clear_file_cache()`: status check; ONLY READY runs
  `file_cache->clear()` into `result.report` (cc:112-:113).
- cc:118-:144 `post_init()`: `reset()` then `MimeSession::init()` (cc:121)
  BEFORE any conf check; `get_file_config()` null -> return (cc:123-:126);
  lazy cache: `new FileCache(conf->max_files_cached)` + shadow + timeouts
  (cc:128-:134); `file_capture_enabled` -> `FileCapture::init(memcap,
  block)` + shadows (cc:136-:141); `conf->snort_protocol_id = sc->
  proto_ref->find("file_id")` (cc:142-:143 — unconditional proto arm).
- cc:146-:169 `verify_reload(sc)`: reset; `get_file_config(sc)` null
  return (cc:149-:152); shadow compare max_files_cached -> ReloadError
  (cc:154-:156); capture pair (memcap, block) compared ONLY when
  `file_capture_enabled` (cc:157-:163); UNKNOWN_PROTOCOL_ID re-arm via
  proto_ref find (cc:165-:168).
- cc:171-:181 `close()`: delete + null cache (cc:173-:177);
  `MimeSession::exit()` (cc:179); `FileCapture::exit()` (cc:180).
- cc:183-:187 `thread_init()` -> `file_stats_init()`; `thread_term()` ->
  `file_stats_term()` (single-expression bodies, brace-on-line quirk).
- cc:189-:192 `enable_file_type()` (relaxed atomic store); cc:194-:197
  `enable_file_signature()`; cc:199-:204 `enable_file_capture()` —
  comment cc:199 "also enable file signature", cascade call cc:203.
- cc:206-:209 `is_file_service_enabled()`: return
  `file_type_id_enabled.load() or file_signature_enabled` — **2-OR ONLY,
  the capture flag NOT included** (donor witness drift, §2).
- cc:211-:225 `get_max_file_depth(FileConfig* fc)`: `fc ? fc :
  get_file_config()`; null -> -1; `file_depth > 0 ? file_depth : -1`.
- cc:227-:252 `set_max_file_depth(sc)`: null return; type-on ->
  `file_depth = file_type_depth` (cc:234-:237); sig-on AND
  `file_signature_depth > file_depth` -> raise (cc:239-:243);
  `file_depth > 0` -> `file_depth++` "extra byte" (cc:245-:249); bare
  `return;` (cc:251).
- cc:254-:270 `namespace snort { uint64_t get_file_processed_size(Flow*)`
  — free function, NOT a FileService member: get_file_flows -> null 0;
  get_current_file_context -> null 0; `context->get_processed_bytes()`.

---

## 2. Donor-closure diff vs tools/fpolicy_harness + witness NEW/KEEP table

### 2.1 cp / compile-loop deltas (the ONLY mechanical deltas to the donor script)

- cp braces build.sh:87 gains `file_service.cc` (the `.h` already rides
  there — NEXT.md:112 "cp delta = file_service.cc appended to the braces +
  the loop"). Row TU compiles VERBATIM: 0 UNIT_TEST/0 TEST_CASE
  hard-assert pins (self-check pattern build.sh:669-:671 style; 17v/17w/
  17x precedent).
- objs loop build.sh:426 gains `file_service` (plain compile; no dir
  special-case in the `case $f` line :427).
- Header cp's (§0.2, ALL compile-only): `src/main.h` -> `$C/main/`,
  `src/mime/file_mime_process.h` + its 8 transitive mime/flowz-cluster
  headers, `src/search_engines/search_tool.h` + `framework/mpse.h` +
  `search_engines/search_common.h`. RECOMMENDED real-cp: `src/target_based/
  snort_protocols.cc` -> `$C/target_based/` (the .h is ALREADY cp'd,
  build.sh:107 target_based dir; the added TU's residue §0.5 = zero app
  NEW; it retires the need for a 5th witness). Fallback if reviewers
  prefer the minimal cp story: a 5th witness body for
  `ProtocolReference::find` (3 lines) — but the real TU costs nothing AND
  the Rust twin at `src/target_based/snort_protocols.rs:41-:141` is fully
  ported, so real-TU parity is the better witness.
- FIXACC: no change (file_service.h already :291; the two extra privates
  h:101/h:104 flip is what already lets stubs.cc:584 arms compile today —
  after retirement nothing in stubs.cc touches the privates anymore, but
  KEEP the entry: file_inspect.cc inline getters + the probe read statics
  through the header).
- gate: UNCHANGED BY CONSTRUCTION and MEASURED IDENTICAL (§0.6, md5
  `4826fc2233044a2d5429413faf0ae1af`). Row .o rides the gate link
  (UT-clean -> no duplicate-symbol exclusion, the :652 case-list stays).

### 2.2 Witness table (stubs.cc cites; RETIRE vs KEEP vs NEW)

**RETIRE (dup-symbol rule R5 — the real `file_service.o` T/B/D-collides
17+6=23 symbols; scratch DEMO: naive full link = 142 "multiple definition"
lines, the FileService-attributable residue = exactly the 23 below; the
`nm` intersection file_service.o ∩ stubs.o = 49 symbols, 23 hard + 26
mergeable W-template plumbing):**

| stubs.cc | symbol | real def |
|---|---|---|
| :584 | `FileService::file_type_id_enabled` (B) | cc:48 |
| :585 | `file_signature_enabled` (B) | cc:49 |
| :586 | `file_capture_enabled` (B) | cc:50 |
| :587 | `file_processing_initiated` (B) | cc:51 |
| :588 | `file_cache` (B) | cc:53 |
| :589 | `decode_conf` (D) | cc:54 |
| :590-:595 | `init post_init verify_reload close thread_init thread_term` (T, printf liveness) | cc:61-:187 |
| :596-:597, :602 | `enable_file_type enable_file_signature enable_file_capture` (T) — the NEW17x cascade body (:602) matched the real cc:200-:204 EXACTLY; the retirement loses nothing | cc:189-:204 |
| :603-:604 | `is_file_service_enabled` (T) — NOTE witness = 3-OR, real = 2-OR (§5 R3) | cc:206-:209 |
| :605 | `get_max_file_depth` (T) — passthrough `return g_max_file_depth` | cc:214-:225 |
| :606-:633 | `set_max_file_depth` (T) — the NEW17w INSTRUMENTED replica of the REAL walk + `g_max_file_depth`/`SMD conf=` readout arms. The 17w/NEXT.md:123 "INSTRUMENT it, don't retire" ruling is SUPERSEDED here: the real body now links; keep the INSTRUMENTATION, not the body — move the `g_max_file_depth = file_config->file_depth` readout + probe arms to the probe (post-call snapshot via the real statics) OR an extern "C" readout that walks the real config after calling the real setter. The instrumented replica also lives on the Rust side (file_inspect.rs:230-:267, finspect vectors `SMD conf=` x7 lines) — that frozen oracle stays (test-side, not harness). | cc:227-:252 |
| :634 | `collect_cache_usage` (T, empty) | cc:76-:84 |
| :635-:636 | `get_file_cache_clear_status` (const UNAVAILABLE) / `clear_file_cache` (empty) | cc:86-:116 |
| :637 | `reset` (T, empty) | cc:66-:74 |
| :711-:727 | `snort::get_file_processed_size` (T) — verbatim copy of cc:256-:268 | cc:256-:269 |

Keep the `namespace snort { }` wrappers and comment banners; the
extern-"C" arms `fcache_set_file_cache` (:639), `fcache_set_max_file_depth`
(:732), `fcache_set_file_service` (:735-:742) keep working VERBATIM — they
name `FileService::*` statics, which now resolve to the REAL defs
(scratch-proven: retired-stubs TU links fine against the real row .o).

**KEEP (resident witnesses the real row TU calls but does NOT define):**
- `ReloadError` :123 (row calls x3, cc:155/:160/:162) — prints "WITNESS
  ReloadError " to stdout; the verify_reload vectors ride it.
- `SnortConfig::get_conf` :55 (cc:89/:142).
- `FlowData::create_flow_data_id` :753 + `FlowData::flow_data_id` :752
  (via inlined `FileFlows::init()` at cc:63).
- `SnortConfig::get_static_name` :57 (via the new snort_protocols.o, §0.5).
- `get_network_policy` :697-:698 + `NetworkPolicy::get_base_file_policy`
  :700-:701 — answer to the recon question: **NO retirement**. `get_base_
  file_policy` is DEFINED at src/main/policy.cc:74 (class NetworkPolicy)
  and CALLED only from file_flows.cc:150; the row TU neither defines nor
  references it (row .o `nm` intersection = no NetworkPolicy symbols;
  residue list has no `get_base_file_policy`). Witness survives 17y
  untouched.
- Flow single-slot graft :705-:709, IMGR block :445-:466 (acquire /
  get_file_inspector / release), fake clock, instance arms, ConfigLogger,
  DetectionEngine, thread-config arms — ALL unchanged.

**NEW (the 4 witness bodies of §0.5; minimal shapes):**
1. `bool main_packet_threads_fully_paused()` — armable
   `int g_pause_witness` setter extern-C (`fsvc_set_paused`); print
   `WITNESS packet_threads_fully_paused=<v>` ONLY when the clear-status
   probe arms reach it (determinism). NEVER cp `src/main.cc` (the real
   body :325 walks `pigs`/Analyzer — monolith).
2/3. `void MimeSession::init()/exit()` — print pair
   (`WITNESS MimeSession::init|exit`). mime row stays queued; do NOT cp
   any mime .cc (NEXT.md:126-:131). The real init (file_mime_process.cc:
   :948) news a SearchTool over mpse — exactly the drag the NEXT.md:133
   verdict scoped out, and it appears ONLY as a call (header include
   cc:38 search_tool.h is compile-only, ZERO symbol use — measured in the
   residue: no SearchTool/mpse entries).
4. `Inspector* InspectorManager::get_inspector(const char*, Module::
   Usage)` — print + return the armed `g_stub_file_inspector` (reuse the
   :432 toggle) or null. cc:68 is the ONLY row-side call (reset guard);
   donor stubs today carry acquire/get_file_inspector/release but NOT
   get_inspector (NEXT.md:139-:142, verified by grep this recon).

Residue pin block (mirror build.sh:620-:624): row residue 47 U total,
app-residue after `comm -23` against objs+stubs_new = 0 (or 5 before the
new-witness objs — pin whichever link order, state it in the script).
Landmine pin (R5 INVERSION, mirror :632-:634): `nm -C file_service.o |
grep -cE '^[0-9a-f]+ T (FileService::(init|post_init|verify_reload|close|
thread_init|thread_term|enable_file_type|enable_file_signature|
enable_file_capture|is_file_service_enabled|get_max_file_depth|
set_max_file_depth|collect_cache_usage|get_file_cache_clear_status|
clear_file_cache|reset)|snort::get_file_processed_size)'` -ge 17 AND the
INVERTED pin `nm -C stubs.o | grep -cE ' T (snort::FileService::|
snort::get_file_processed_size)'` -eq 0 (this row INVERTS 17x's
zero-retirement guard: retirement is mandatory — the §0.6 demo link prints
the 23-pair collision if a witness regresses).

---

## 3. Rust landing per symbol (grep-verified sites; port-vs-seam verdicts)

Inventory sites (measured `grep -rn 'FileService\|file_service' src/
tests/`): the `FileServiceLite` home `src/file_api/file_lib.rs:933-:1031`;
`FileEnvLite` :1123-:1210 (svc slot :1158, max_file_depth seam :1153-
:1156); `get_max_file_depth` passthrough doc+body :1241-:1254; free
`get_file_processed_size` `file_flows.rs:123-:137` (+ re-export
`file_api.rs:445-:447`); `file_inspect.rs:230-:267` instrumented
`set_max_file_depth`, :328-:361 configure arm, :411-:424 svc gates;
`file_stats.rs:141-:157` witness hook + :180-:186 init/term;
`FileConfigView` 17u (`file_lib.rs:810-:811` file_depth source, :917-:930
view bridge); `file_api.rs:168-:174` `FileCacheClearReport` (fccr=16 pin,
fapi_parity_test.rs:85); `file_cache.rs:116-:120` re-export + :1727-:1730
`clear()`; `target_based/snort_protocols.rs:41-:141` (find :141 — REAL);
`file_flows.rs:327` `FileFlows::init` (REAL via env Cell
file_flow_data_id); `file_capture.rs:303/:439` init/exit (REAL, 17s
single-thread async seam posture).

Per-symbol verdicts:
- **enable trio + cascade (cc:189-:204)** — LANDED REAL in 17x
  (`file_lib.rs:990-:1008`, cascade at :1006-:1007, fpolicy V3/V4 pins).
  17y = zero Rust edit; the real TU now CONFIRMS the port (the harness
  witness :602 that the 17x port mirrored is now retired in favor of the
  real body — vectors must survive the swap; §0.6 proves the gate side,
  the fsvc probe re-pins V3/V4 semantics against the real TU in NEW
  vectors).
- **is_* inline getters (h:85-:87)** — landed as `is_file_*_enabled`
  (:1009-:1017). KEEP.
- **`is_file_service_enabled` (cc:206-:209)** — landed 2-OR (:960-:963)
  = REAL semantics EXACTLY (the C donor witness 3-OR was the drift; Rust
  never copied it). KEEP; new fsvc vectors pin the quirk: capture-only
  arm -> false (drift line, §5 R3).
- **statics trio + file_processing_initiated + file_cache** — landed as
  FileServiceLite fields (:944-:952); `file_processing_initiated` stays
  UNPORTED (dead upstream, §1 cc:51 — add a KNOWN DEVIATIONS line: not a
  field, zero readers by grep).
- **`decode_conf` (h:99, cc:54)** — STAYS SEAM (no DecodeConfig anywhere
  in src/ — measured grep-0; owners are the mime/service-inspector rows).
  file_service.h's static is harness-side only. No Rust change.
- **`init` (cc:61-:64)** — REAL-port as `FileServiceLite::init(env)`
  calling the landed `FileFlows::init` arm (file_flows.rs:327 through
  env.file_flow_data_id) — one-liner over landed pieces.
- **`reset` (cc:66-:74)** — REAL-port with the IMGR seam:
  `FileEnvLite.imgr` (ImgrRc :1141) grows an `get_inspector` arm
  mirroring the 4th NEW witness; guard + 3-field clear verbatim.
- **`post_init` (cc:118-:144)** — SPLIT: cache-lazy arm + timeouts
  (cc:128-:134) REAL over landed FileCache/file_cache seam (17p);
  `MimeSession::init()` = OUT-OF-CLOSURE, model as an explicit
  `MimeSessionInit` trait seam on FileServiceLite/FileEnvLite that the
  tests pin as a print (same pattern as `PublishApi`), NOT a fake success
  body; the proto arm cc:143 REAL over `ProtocolReference::find`
  (snort_protocols.rs:141 — landed; FileConfigView/FileConfigLite gains a
  snort_protocol_id field: measured, fp_eval already carries
  `snort_protocol_id` call-through file_lib.rs:125-:136, so the field
  exists on the call-shape side but the config field itself is NEW —
  land it 17y and pin `conf.snort_protocol_id == find("file_id")`).
  `FileCapture::init` cc:138 = landed file_capture.rs:303 (thread seam
  deviation already ruled 17s).
- **`verify_reload` (cc:146-:169)** — REAL-port: the ResetAndCheck walk +
  3 ReloadError report lines through the driver-owned log sink (finspect
  test driver already re-emits "WITNESS ErrorMessage" arms,
  finspect_parity_test.rs:83). Shadow statics cc:57-:59 land as FileEnvLite
  Cells (`max_files_cached`, `capture_memcap`, `capture_block_size`) —
  they are ONLY observable through the reload-mismatch vectors.
- **`close` (cc:171-:181)** — REAL-port minus mime: cache drop + null
  (cc:173-:177), `FileCapture::exit` seam (landed :439), MimeSession::exit
  trait seam pin.
- **`thread_init/thread_term` (cc:183-:187)** — REAL one-liners over
  landed `file_stats_init/file_stats_term` (file_stats.rs:180-:186).
- **`get/set_max_file_depth` (cc:214-:225/:227-:252)** — get: the seam
  passthrough `FileEnvLite::get_max_file_depth` (:1241-:1254) STAYS
  (the fflows J/H vectors pin passthrough -5/0 — frozen, cannot re-pin),
  but NEW REAL `get_max_file_depth(fc: Option<&FileConfigLite>)` lands on
  FileServiceLite mirroring the 17x enable-trio pattern: body
  `fc.unwrap_or(env-config)` -> null -1 -> `>0 ? depth : -1`; fsvc
  vectors pin the arms. set: the landed instrumented replica
  (file_inspect.rs:255-:267) feeds frozen finspect `SMD conf=` lines —
  KEEP the trait instrumented for those tests, and add the verbatim real
  body as the canonical method the new fsvc vectors drive (same dual-view
  ruling the 17x PLAN made for the enable arms: witness arms stay
  byte-verbatim for frozen replays, REAL bodies canonical going forward).
- **`collect_cache_usage` (cc:76-:84)** — REAL-port on the landed stats
  stack: `src/utils/stats/snapshot.rs` Builder :142 + `counter` :193 exist
  (NEXT.md:136-:139 "Rust side DONE" verified); file_stats.rs:156-:157
  witness hook gets the real body (null-cache return, entries>0 gate,
  counter name "File cache entries").
- **`get_file_cache_clear_status` + `clear_file_cache` + the enum/pair
  (h:47-:62, cc:86-:116)** — NEW REAL landing: `FileCacheClearStatus`
  enum class (u8 repr, values §0.8) + `FileCacheClearResult { status,
  report }` land beside `FileCacheClearReport` in `file_api.rs` (canonical
  home 17v). Body: `max_procs`/`mp_dbus` read off the Rust SnortConfig
  seam (`mp_dbus` Cell ALREADY exists file_lib.rs:1148; `max_procs` NEW
  field on the same seam), `file_cache` null check on svc, PAUSE
  PREDICATE = seam `Cell<bool> packet_threads_fully_paused` on
  FileServiceLite (out-of-closure analyzer; harness witness arms it —
  §5 R6), then landed `FileCache::clear()` (file_cache.rs:1729) for READY.

Vectors plan (fsvc probe V-arms, ~28-34 lines, new file NEVER touches
fpolicy's 27 L): V1 clear-status 5-arm ladder (conf-null / max_procs=2 /
mp_dbus=1 / cache-null / unpaused -> 4 statuses + READY with
fsvc_set_paused 1 + a populated cache -> `cleared freed/evicted` line via
the real FileCache::clear print); V2 enable-cascade + is_file_service
2-OR quirk (capture-only -> svc=0; REAL-vs-witness drift pin); V3 depth
get real ladder (null conf -1, 0 -> -1, 1460 -> 1460, fc-arg arm); V4 set
ladder (type-on copy, sig-gt raise, ++, neg stays); V5 verify_reload
ReloadError x3 arms (shadow drift) + UNKNOWN_PROTOCOL_ID re-arm;
V6 post_init arms over harness null conf (early return BEFORE Mime? — NO:
measured cc:120-:121 order = reset+Mime FIRST, pin "WITNESS MimeSession::
init THEN conf-null return"); V7 collect_cache_usage counter line (0
entries -> no line, >0 -> `File cache entries` — print counter name);
V8 reset gate (IMGR get_inspector armed -> statics NOT cleared).

---

## 4. Frozen-oracle audit (tests/ witness-line asserts, grep-counted this recon)

| token | tests/ files (count) | vectors | verdict |
|---|---|---|---|
| `SMD conf` | finspect_parity_test.rs:2 (driver push arms :70-style) | finspect vectors 7 lines | SAFE — printed by the Rust TEST driver/instrumented trait, not by the retired C witness; C retire cannot move it |
| `svc t=` | fpolicy_parity_test.rs:4 | fpolicy vectors 3 (V2/V3/V4, md5-pinned) | SAFE on retire — the lines print through the INLINE h:85-:87 getters (unchanged semantics: real statics == witness statics shapes); the 2-OR is_file_service_change is NOT pinned there (every captured svc line has t or s lit when c lit: V4 `s=1 c=1`) |
| `IMGR acquire` | fcache:2, fcshare:2, fctx:3, fflows:1 | fcache 66, fcshare 6, fctx 39, fflows 17, filib 15 | NOT TOUCHED — acquire witness ≠ get_inspector; keep block bytes-ident in stubs |
| `POLICY base_file_policy` | fctx:3, fflows:4 | fctx 35, fflows 4 | SAFE — witness pair KEPT (§2.2) |
| `WITNESS ReloadError` | 0 | 0 | verify_reload path never pinned today; new fsvc vectors introduce pins fresh, no frozen edits |
| `FileService init/post_init/...close` prints | 0 | 0 | lifecycle witness prints grep-0 everywhere — retirement moves ZERO frozen lines |

**Verdict: ZERO frozen-file edits for the retirements + witness swaps.**
The only vectors risk is the `V4_load_cap` cascade line re-emitted by the
fsvc probe against the REAL cascade body — identical output expected
(fpolicy stubs.cc:602 already replicated cc:200-:204; scratch closure ran
the same code path family).

---

## 5. Risks (cites)

- **R1 static-init order**: `decode_conf` (cc:54, D, non-trivial ctor)
  vs file_inspect.o inline getters loading the B-section statics at
  static-init time: never happens (all readers are runtime paths); the
  atomic<bool> is dynamic-init too (cc:48 ctor(false)) — inline
  `is_file_type_id_enabled()` BEFORE init() would read zero-init .bss
  (scratched gate proved: md5 identical, no init-order diag). No action;
  pin in vectors by calling getters pre-init once (V2 arm 0).
- **R2 heap posture**: real `post_init` NEWS FileCache (cc:130) and
  `close` deletes (cc:175); leak-if-no-close like the 17w R2 rule — probe
  arms cache via `fcache_set_file_cache` (donor arm, still works) or
  calls post_init exactly once then close (pin the print pair order).
  NEVER hand `post_init` the static g_stub_file_config with new-cache
  side-effects unless close follows (R2 precedent).
- **R3 is_file_service_enabled drift**: donor witness 3-OR
  (stubs.cc:604) vs real 2-OR (cc:208): any OLD harness re-running the
  donor scripts stays 3-OR; the 17y link CANNOT keep both (R5) — accept
  the real semantics and pin capture-only->false in NEW vectors; existing
  fpolicy fctx/fflows vectors never hit the drift condition (§4) — but
  if any FUTURE donor-regression run shows a `svc` line difference ONLY
  when c=1,t=0,s=0, that is this drift, not a bug.
- **R4 passthrough get_max_file_depth**: the retired witness answered
  `g_max_file_depth` (:605) for 17q-17x vectors (file_lib.rs:1241-:1254
  "restated in the plan row until FileService links as a real TU" — THIS
  row is that row); with the real .o linked, `get_max_file_depth()` in a
  gate/probe run answers the CONFIG value, not the arm — g_max_file_depth
  drift is invisible to the gate (no such line) but probe H/J-style arms
  that expect passthrough must re-route through
  `fcache_set_file_config_depth()` (arm the real config) or keep the old
  fflows/fcache harnesses UNBUILT (donor scripts untouched — each harness
  has its own copy tree; the drift is per-row by construction).
- **R5 dup-symbol landmine CONFIRMED numeric**: 23 hard collisions
  (17 T + 6 B/D, §2.2); naive co-link demo = 142 diagnostics (scratch-
  measured). The landmine assert inverts this row (§2.2) — any attempt to
  keep a FileService witness body next to the real .o fails the build.
- **R6 pause semantics**: real def (src/main.cc:325-:340) walks the
  analyzer/pigs monolith — recommend: witness = armable bool (harness),
  Rust = `Cell<bool>` seam on the svc/config view; do NOT port
  `Analyzer::is_fully_paused`; document in KNOWN DEVIATIONS with the
  main.cc cite. The status check is const-by-contract (h:94) — assert the
  vectors show cache-unchanged around each call.
- **R7 THREAD_LOCAL counts**: `file_counts`/`file_stats` (file_stats.cc:
  :45-:46) live in the REAL file_stats TU (already linked since 17s) —
  the row only forwards thread_init/term; no new thread-local witness;
  Rust side = 17p single-thread deviation already ruled
  (file_stats.rs:170-:186 + FileServiceLite atomics note file_lib.rs:933-
  :935).
- **R8 header drag compile-only risk**: `search_tool.h`/`mpse.h` pull
  nothing at link time TODAY (grep-0 use bodies, §0.2) — pin
  `nm -u file_service.o | grep -c mpse` = 0 in the residue block so a
  future upstream use doesn't silently drag a SearchTool witness.
- **R9 gate exposure**: real close()/post_init()/clear_file_cache() run
  NOTHING at static time; the gate never calls the lifecycle (34 IMGR
  acquires unchanged, §0.6 md5). Any future probe call to FileCapture::
  init (cc:138) spawns the async writer (donor: NEVER called, stubs.cc:
  :641-:645 posture) — probe arms keep `file_capture_enabled=false`
  before post_init except ONE vector pair init/exit (the 17s
  single-threaded donor arms mempool via :646 instead).

---

## 6. Session ritual (mirror fpolicy PLAN §6)

1. `mkdir tools/fsvc_harness`; `cp` donor build.sh; apply §2.1 deltas
   (grep-pinned line anchors :87/:426/:291 unchanged); NEW17y comment
   header with THIS PLAN's measured numbers (47 U = 14 app-resident + 3
   stub + 5 NEW-app + 25 plumbing; 23 retirements; new witnesses = 4;
   real-cp = snort_protocols.cc).
2. stubs.cc = donor VERBATIM + the two retirement blocks (§2.2 cites) +
   the 4 NEW witnesses; probe.cc fresh V1-V8 (§3 vectors plan);
   vectors.txt NEVER copied from donor (fresh, committed, md5 pinned).
3. Hard-pins: row TEST_CASE/UNIT_TEST 0/0 x2 files; row residue comm -23
   count; T-def >=17; stubs survivor ==0; gate tail
   "All tests passed (114 assertions in 22 test cases)" + md5
   `4826fc2233044a2d5429413faf0ae1af` + 34 IMGR/0 FileInspect greps;
   hygiene gate (no 0x[0-9a-f]{6,}) verbatim.
4. Rust per §3 verdicts; KNOWN DEVIATIONS: decode_conf seam,
   file_processing_initiated dead-static, pause-predicate Cell, mime
   trait seam, max_file_depth dual-view (extend 17x ruling); cargo test /
   clippy 0; fsvc_parity_test.rs replay; NEXT.md row-17z scoping pass.
