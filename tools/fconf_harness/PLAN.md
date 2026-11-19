# fconf_harness PLAN — row 17u: file_api/file_config.{h,cc} (the config-aggregator row, probe-vectors-only)

Ground truth: /opt/data/snort3-src @ fe29cbe (READ-ONLY). Port: /opt/data/snort3-rust @ 5f8f147.
Donor: tools/fcshare_harness (row 17t; 17p/17q/17r lineage). This PLAN mirrors fcshare PLAN §1–§10.

## 1. Scope definition + size (measured)

- `src/file_api/file_config.h` — 80 lines (3454 B): 11 `DEFAULT_*` macros (:30–:40),
  `FILE_ID_NAME`/:42 + `FILE_ID_HELP`/:43, `class FileConfig` (:45–:76, 18 public fields +
  1 private `FileIdentifier fileIdentifier` at :75), 2 free decls: `file_type_name(uint32_t)`
  (:78) and `get_file_config(const snort::SnortConfig* sc = nullptr)` (:79).
- `src/file_api/file_config.cc` — 128 lines (3908 B): 5 method bodies + free `file_type_name`
  + `get_file_config` + 2 `snort::`-namespace API shims. No statics, no globals, no OWNED state
  (the TU is a pure forwarder + one heap string per name lookup).
- Header includes (:26–:28): `main/snort_config.h`, `detection/detection_engine.h`,
  `file_api/file_identifier.h`. .cc includes (:30–:37): its own header,
  `managers/inspector_manager.h`, `main/snort_config.h`, `parser/parse_utils.h`,
  `file_api/file_flows.h`, `file_api/file_inspect.h`.

## 2. TEST_CASE inventory (measured)

`grep -c 'TEST_CASE\|UNIT_TEST'`: file_config.h = 0, file_config.cc = 0.
**0 TEST_CASE / 0 `#ifdef UNIT_TEST` fragments → probe-only ground truth row** (same posture
as fcshare 17t). Gate for the donor copy: `file_config.cc` is ALREADY compiled in the fcshare
harness (cp list build.sh:35, syntax loop build.sh:367, artifact `copy/file_api/file_config.o`
exists) — see §3/§8: row 17u is a probe-arms row, not a cp-onboard row.

## 3. Closure + self-verified compile/nm (this recon, exact commands)

Recipe used (scratch header-only graft tree, fcshare copy headers at HEAD of copy/):

```
mkdir tree; (cd fcshare_harness/copy && find . -name '*.h' -o -name '*.hpp') -> tar into tree
cp copy/{daq_common.h,config.h} tree/ ; cp src/file_api/file_config.{cc,h} tree/file_api/
g++ -std=c++17 -O0 -g -w -Itree -fsyntax-only tree/file_api/file_config.cc   # SYNTAX_OK
g++ -std=c++17 -O0 -g -w -Itree -c  tree/file_api/file_config.cc -o file_config.o  # COMPILE_OK (1,491,072 B)
nm -u --demangle file_config.o | wc -l  ->  30 undefined
```

App-residue (6) vs libstdc++/libgcc residue (24: string dtor plumbing, `_Unwind_Resume`,
`__cxa_*`, `operator new/delete`, `strlen`, `__throw_*`):

| residue symbol | resolved by (harness) |
|---|---|
| `FileIdentifier::add_file_id` / `find_file_type_id` / `get_magic_rule_ids_from_type` / `get_rule_from_id` | REAL `copy/file_api/file_identifier.o` (cp list build.sh:35) |
| `snort::InspectorManager::get_file_inspector(const SnortConfig*)` | stubs.cc:364 witness (fcshare donor) |
| `snort::SnortConfig::get_conf()` | harness snort_config.h shim (build.sh:93–:115 graft) |

**Closure verdict: VERIFIED by -fsyntax-only + scratch `-c` .o + nm -u — app residue maps 1:1
onto symbols the fcshare donor already provides; ZERO new closure work.** Note
`FileTypeBitSet = std::bitset<1024>` surfaces in the demangled mangled-residue signature
(get_magic_rule_ids_from_type) — confirms file_identifier.h:84 shape.

## 4. `#ifdef UNIT_TEST` fragment table

None (0 occurrences in both files). No ut-only members to pin or retire.

## 5. Surface map (all cited to fe29cbe)

**Macros (h:30–:43):** `DEFAULT_FILE_TYPE_DEPTH 1460` (:30), `DEFAULT_FILE_SIGNATURE_DEPTH
10485760 = 10 MiB` (:31), `DEFAULT_FILE_SHOW_DATA_DEPTH 100` (:32), `DEFAULT_FILE_BLOCK_TIMEOUT
86400 /*1 day*/` (:33), `DEFAULT_FILE_LOOKUP_TIMEOUT 2` (:34), `DEFAULT_FILE_CAPTURE_MEM 100
// 100 MiB` (:35), `DEFAULT_FILE_CAPTURE_MAX_SIZE 1048576 // 1 MiB` (:36),
`DEFAULT_FILE_CAPTURE_MIN_SIZE 0` (:37), `DEFAULT_FILE_CAPTURE_BLOCK_SIZE 32768 // 32 KiB`
(:38), `DEFAULT_MAX_FILES_CACHED 65536` (:39), `DEFAULT_MAX_FILES_PER_FLOW 128` (:40),
`FILE_ID_NAME "file_inspect"` (:42), `FILE_ID_HELP "configure file inspection"` (:43).

**Members (h:55–:72, declared order — 17 fields):**
file_type_depth i64 (:55) · file_signature_depth i64 (:56) · file_block_timeout i64 (:57) ·
file_lookup_timeout i64 (:58) · block_timeout_lookup bool (:59) · capture_memcap i64 (:60) ·
capture_max_size i64 (:61) · capture_min_size i64 (:62) · capture_block_size i64 (:63) ·
file_depth i64 (:64) · max_files_cached **i64** (:65) · max_files_per_flow **uint64_t** (:66) ·
show_data_depth i64 (:68) · trace_type bool (:69) · trace_signature bool (:70) ·
trace_stream bool (:71) · snort_protocol_id SnortProtocolId (:72, `UNKNOWN_PROTOCOL_ID = 0`
per target_based/snort_protocols.h:47). Private: `FileIdentifier fileIdentifier` (:75).
NOTE: the Rust docs' cites drift ~2 lines (file_cache.rs:313 calls trace_type "file_config.h:71"
— it is :69 at fe29cbe; file_lib.rs:837 "file_config.h:70-74" is really :69–:72). PORT child:
keep the semantic comment, refresh the numbers when touching.

**Methods (cc bodies):**
- `find_file_type_id(buf,len,file_offset,context)` cc:41–:45 → forward to `fileIdentifier.find_file_type_id`.
- `process_file_rule(const FileMeta&)` cc:48–:51 → `fileIdentifier.add_file_id`.
- `get_rule_from_id(uint32_t) const` cc:53–:56 → `fileIdentifier.get_rule_from_id`.
- `get_magic_rule_ids_from_type(type,version,ids_set) const` cc:58–:62 → fileIdentifier forward.
- `FileConfig::file_type_name(uint32_t) const` cc:64–:78: `SNORT_FILE_TYPE_UNKNOWN` → literal
  `"Unknown file type, done"` (:66–:67); `SNORT_FILE_TYPE_CONTINUE` → `"Undecided file type,
  continue..."` (:69–:70); table hit → `info->type` (:72–:75); miss → `""` (:77).
- FREE `file_type_name(uint32_t)` cc:80–:87: `get_file_config()` null arm → **`"NA"`** (:86).
- `get_file_config(const SnortConfig* sc)` cc:89–:100: `sc` null → `SnortConfig::get_conf()`
  (:91–:92); `InspectorManager::get_file_inspector(sc)` cast (:94); `fi ? fi->config : nullptr`
  (:96–:99).
- `snort::get_magic_rule_ids_from_type(..., SnortConfig* sc)` cc:104–:113: conf hit → member
  call; **null arm → `ids_set.reset()`** (:112).
- `snort::set_rule_id_from_type(sc, id, type, category, version, groups)` cc:117–:127:
  constructs `FileMeta rule(...)` (:124) then `conf->process_file_rule(rule)`; conf null →
  silent no-op. cppcheck-suppress comments (:105/:115–:118) pin by-value std::string params —
  ABI-pinned signatures, do not "fix".

## 6. Consumer map (ground truth) + Rust seam sites (exact lines)

**C consumers — `grep -rn 'FileConfig\b' src/file_api/*.cc *.h` (this recon):**
- file_cache.cc:322 (`inspector->config` → `file->set_config`) · :669
  (`get_file_config(p->context->conf)`) · :1186 (**TEST_CASE-only `FileConfig config;`** inside
  file_cache.cc's UNIT_TEST region — lives with row 17m's cpp file, not this TU).
- file_flows.cc:322 (`get_file_config(SnortConfig::get_conf())` → :325 max_files_per_flow gate).
- file_inspect.cc:90 `file_config_show(const FileConfig*)` — reads ALL twelve depth/timeout/
  capture/cached fields (:91–:110+, ConfigLogger).
- file_lib.cc:598 · :1016 (`const FileConfig* const conf = get_file_config()`).
- file_module.cc:197 (`fc = new FileConfig`) · :263 `FileIdModule::load_config(FileConfig*& dst)`
  — the ONLY mutator site: 15 setters file_module.cc:200–:242 (every field except
  `file_depth`/`snort_protocol_id`; set from `Value::get_int64/get_uint64/get_bool`).
- file_service.cc:123 · :149 · :214–:229 (`get_max_file_depth`: `file_config->file_depth > 0 ?
  file_depth : -1`; `set_max_file_depth` writes `file_depth` — the two file_depth readers/writers
  outside file_module).
- Headers: file_inspect.h:36 `FileConfig* config` (the FileInspect member get_file_config reads);
  file_lib.h:41 fwd, :213–:214 set/get_config, :235 member; file_module.h:61/:82; file_segment.h:33
  fwd; file_service.h:37 fwd, :89 static member sig.
- Includers of file_config.h: file_cache.h, file_flows.cc, file_inspect.cc, file_lib.cc,
  file_log.cc, file_module.h, file_stats.h, file_config.cc itself, **src/mime/file_mime_config.cc**.
- Non-file_api function consumers: ips_options/ips_file_meta.cc:129 (`set_rule_id_from_type`),
  ips_options/ips_file_type.cc:196/:205/:214 (`get_magic_rule_ids_from_type`),
  mime/file_mime_config.cc:151 (`get_file_config(sc)` → get_max_file_depth).

**Rust seam sites today (`grep -n 'FileConfigView|file_config' src/file_api/*.rs`):**
- file_cache.rs:100–:108 — the three DEFAULT_* constants mirrored (BLOCK_TIMEOUT/LOOKUP/
  MAX_FILES_CACHED with C line cites).
- file_cache.rs:266 `PacketView::conf: FileConfigView` (17p pinned by-value view).
- file_cache.rs:319–:341 `struct FileConfigView` (7 Copy fields: block_timeout_lookup, mp_dbus
  [SnortConfig side], trace_type, trace_signature, trace_stream, show_data_depth,
  file_signature_depth); :343–:358 **hand-written `Default`** (derive trap already retired per
  :334–:339 doc); :360–:376 `file_type_name` harness-view deviation (table ids → `""`; the
  FileIdentifier table does NOT ride the Copy view — pinned deviation, doc at :361–:367).
- file_cache.rs:491 `trait { fn config(&self) -> Rc<RefCell<FileConfigView>>; }` · :1168–:1170
  pub-side `conf: Rc<RefCell<FileConfigView>>` · :1211 default-built.
- file_lib.rs:801–:812 — DEFAULT_* consts (mirrors h:40/:30/:31/:32/:35–:38).
- file_lib.rs:820–:848 **`FileConfigLite`** = full 17-field + FileIdentifier mirror of the C
  class (row 17q); :850–:873 hand-written `Default`; :875–:894 `get_rule_from_id` +
  `FileConfigLite::file_type_name` (real 4-arm C transcription incl. `""` miss).
- file_lib.rs:896–:910 **`file_config_view_of(&FileConfigLite) -> FileConfigView`** — the 17p
  bridge (copies 6 shared fields, `..Default::default()`).
- file_lib.rs:1070–:1072 `FileEnvLite::file_config: Option<Rc<RefCell<FileConfigLite>>>` (:1113
  default None) · :1141–:1146 `get_file_config()` (null-while-no-inspector arm, file_config.cc:89
  shape) · :1301–:1309 `FileContext.config: Option<Rc<RefCell<FileConfigView>>>` (DEVIATION note
  there: two config types coexist) · :1473 `set_config` · :1523–:1526 free-`file_type_name`
  resolution (`env.get_file_config()` match, the "NA" null arm live) · :2487–:2488, :3007–:3008
  test/driver expect()-arms citing file_lib.cc:1012/:1174 derefs.
- file_flows.rs:222–:229 (`file_type_name` via `env.get_file_config()`; null arm → pinned-absent
  comment) + :660–:665 (driver reads the resolved conf).
- file_stats.rs:147 — `file_type_name(uint32_t)` prose cite (free-global vs member distinction
  already drawn at file_lib.rs:2766–:2772).

## 7. Gate plan + PROBE VECTOR PLAN (labeled arms; 0-TEST_CASE TU → probe-only)

Harness posture: **extend/mirror the fcshare donor, do not rebuild closure** (§3: file_config.cc
cp'd build.sh:35, in syntax loop :367, .o exists). New `copy/file_api/file_config_probe.cc`
(pattern = donor `file_cache_share_probe.cc`), arms appended to vectors.txt (style
`LABEL k=v k=v …`). Fixture = stubs.cc's harness-armed `g_stub_file_config`
(stubs.cc:346–:366, :418 `config = &g_stub_file_config`, :427–:428 `get_harness_file_config()`).

**D — ctor defaults (1 arm; the derive-Default trap is the known killer — pin EVERY field):**
- `D_defaults` = `FileConfig fc;` print all 17 fields (file-private probe pattern from fid donor
  if needed; fields are public so direct print). Vector line pins (see table §7b). Witness:
  `ftype_depth=1460 sig_depth=10485760 ...` one long line.

**Table §7b — EVERY non-zero initializer (file_config.h; derive-Default would clobber all 10):**
| field | init | cite |
|---|---|---|
| file_type_depth | 1460 (DEFAULT_FILE_TYPE_DEPTH) | h:30, h:55 |
| file_signature_depth | 10485760 (10 MiB) | h:31, h:56 |
| file_block_timeout | 86400 (1 day) | h:33, h:57 |
| file_lookup_timeout | 2 | h:34, h:58 |
| capture_memcap | 100 (100 MiB, RAW unit) | h:35, h:60 |
| capture_max_size | 1048576 (1 MiB) | h:36, h:61 |
| capture_block_size | 32768 (32 KiB) | h:38, h:63 |
| max_files_cached | 65536 | h:39, h:65 |
| max_files_per_flow | 128 (uint64_t type!) | h:40, h:66 |
| show_data_depth | 100 | h:32, h:68 |
Zero-arm for contrast: block_timeout_lookup=false h:59 · capture_min_size=0 h:37/:62 ·
file_depth=0 h:64 · trace_* false h:69–:71 · snort_protocol_id=UNKNOWN_PROTOCOL_ID=0 h:72 /
snort_protocols.h:47.

**N — naming/constants (1 arm):** `N_names` = `strcmp(FILE_ID_NAME,"file_inspect")==0` +
`FILE_ID_HELP` literal; CONST line `sizeof(FileConfig)` (pins the embedded FileIdentifier size,
cf. donor CONST-style lines).

**T — FileConfig::file_type_name (4 arms, mirrors L_* string pins):**
- `T1_unknown` = id `SNORT_FILE_TYPE_UNKNOWN` → `"Unknown file type, done"` (cc:66–:67).
- `T2_continue` = id `SNORT_FILE_TYPE_CONTINUE` → `"Undecided file type, continue..."` (cc:69–:70).
- `T3_hit` = process_file_rule(FileMeta{file_id=7,type="exe",...}) then name(7) == `"exe"`
  (cc:72–:75; real file_identifier.o carries the table).
- `T4_miss` = name(999) == `""` (cc:77).

**F — free file_type_name (2 arms, the get_file_config resolution seam):**
- `F5_free_resolved` = with inspector armed (stubs seam) → member path (cc:82–:84).
- `F6_free_null` = InspectorManager::get_file_inspector → nullptr arm → **`"NA"`** (cc:85–:86).
  Needs a stub toggle (stubs.cc witness switch / second stub class) — FIXACC note: if the donor
  get_file_inspector witness is hard-wired (:364), add a probe-settable flag global in stubs.cc
  (witness-delta item, §8).

**G — get_file_config (3 arms):** `G1_explicit_sc` (pass sc → cast path cc:94),
`G2_null_sc_default` (no-arg: `sc = SnortConfig::get_conf()` cc:91–:92 — shim get_conf must be
non-null else fi-null arm), `G3_null_arm` combined with F6 (returns nullptr cc:99).

**M — snort API shims (4 arms):**
- `M1_set_rule` = snort::set_rule_id_from_id(sc, 12, "pdf","cat","v",{"g"}) → later
  get_rule_from_id(12) non-null + file_type_name(12)=="pdf" (cc:117–:127 + FileMeta ctor).
- `M2_set_rule_null` = null-conf arm → silent skip, table stays empty (cc:122 guard).
- `M3_magic_ids` = armed table, get_magic_rule_ids_from_type pins bitset<1024> result
  (cc:104–:110; if fileIdentifier's magictable needs magic-db fixtures, check fid_harness
  vectors for the add_file_id→bitset path before promising a hit — else pin the miss=empty arm).
- `M4_magic_ids_reset` = null-conf → `ids_set.reset()` observable sentinel bits cleared (cc:112).

**S — set-path (load_config) (1 arm):** `S1_load_config_setters` reproduce the 15
file_module.cc:200–:242 assignment targets on a fresh FileConfig; witness round-trip of each
(new values ≠ D_defaults — doubles as the mutate half of the initializer table).

## 8. PORT scoping — transcription plan + seam-close list (no code here)

**Already transcribed (rows 17q/17r did most of this row):** `FileConfigLite` (file_lib.rs:820–
:848, all 17 fields + hand Default :850–:873 + get_rule_from_id/file_type_name :875–:894) and
the DEFAULT_* consts (:801–:812). What row 17u OWNS (the open seams):

1. **Macro consts parity:** `DEFAULT_MAX_FILES_CACHED` + `DEFAULT_FILE_BLOCK_TIMEOUT`/
   `DEFAULT_FILE_LOOKUP_TIMEOUT` live on file_cache.rs:104–:108, the rest on file_lib.rs:801–:812
   — the split is a prior-row artifact (rationale doc'd file_lib.rs:803–:805). Decision for 17u:
   keep the split (file_cache constants 17m-pinned) OR move the trio behind one pub use; do NOT
   duplicate. `FILE_ID_NAME`/`FILE_ID_HELP`: currently absent in Rust — add as pub consts
   (file_lib.rs near :812) if any ported row consumes them (file_module row will).
2. **Free `file_type_name` (file_config.cc:80–:87):** live via `FileEnvLite::get_file_config()`
   resolution at file_lib.rs:1523–:1526 (the "NA" arm is there). Seam verdict: **closed**; 17u
   only needs its probe vectors to re-pin it (F5/F6 labels).
3. **`snort::get_magic_rule_ids_from_type` / `set_rule_id_from_type` (cc:104–:127):** NOT yet in
   Rust (no `get_magic_rule_ids`/`set_rule_id` on FileEnvLite — grep-verified surface: only
   FileConfigLite's member-side :876–:879 exists via file_identifier). PORT 17u adds both
   shims on FileEnvLite with the explicit null arms (`ids_set.reset()` / no-op) — the C null
   arms are observable contract for ips_options consumers.
4. **`find_file_type_id` / `process_file_rule` forwarders (cc:41–:51):** member forwards to
   FileIdentifier; seam = FileConfigLite.file_identifier direct call already available (fid row);
   17u adds the two named methods on FileConfigLite for 1:1 surface parity.
5. **FileConfigView fate (17p seam):** the Copy view (file_cache.rs:319–:341) stays — it is the
   17p-pinned by-value PacketView::conf contract (:266), NOT a fake to retire. The one deviation
   to close if vectors demand: FileConfigView::file_type_name table-miss shortcut (:360–:376) —
   closed unless the T3 probe shows the harness needs member-path names through PacketView; the
   bridge `file_config_view_of` (file_lib.rs:900–:910) already copies 6 of 7 fields.
6. **FileContext.config type duality** (file_lib.rs:1301–:1309 doc admits two Rc config types):
   candidate but NOT mandatory for 17u — swapping FileConfigView→FileConfigLite there re-arms
   every 17p/17r vector; leave open with a named comment unless a T3-via-FileContext vector fails.

**Harness scoping:** new tools/fcconf_harness = fcshare donor build.sh with: probe entry swapped
to file_config_probe.cc; gate link keeps file_config.o (it's in the cp list already — build.sh:35
VERBATIM, zero cp delta); vectors.txt = D/N/T/F/G/M/S arms. Expected witness delta: **zero new
stubs** EXCEPT the F6/G3 get_file_inspector-null toggle in stubs.cc (:364 witness today always
returns the armed stub) — a single probe-settable `g_null_file_inspector` flag there; everything
else (FileIdentifier real .o, SnortConfig::get_conf shim) already present.

## 9. Risks flagged for HARNESS/PORT children

- **R1 derive-Default trap (THE known killer):** 10 fields have non-zero C in-class inits
  (§7b table). Both Rust Defaults are already hand-written (file_lib.rs:850, file_cache.rs:343)
  — any refactor to `#[derive(Default)]` silently zeroes depths and depth-fails every armed
  ladder. Keep hand-written Defaults; probe D_defaults re-pins all 10 numerals.
- **R2 type asymmetry:** max_files_cached is int64_t, max_files_per_flow uint64_t (h:65/:66);
  file_depth default 0 but FileService::get_max_file_depth returns **-1** sentinel at
  file_service.cc:218 — do not normalize to 0. capture_memcap default 100 is a RAW MiB count
  (unit multiply happens elsewhere, h:35 comment) — pin numeral, never "convert".
- **R3 config-string ownership:** FILE_ID_NAME/HELP are C literals for the parser/module layer;
  FileConfig owns no strings itself — only FileMeta::type (in the FileIdentifier table) is heap.
  Rust: `&'static str` consts for the defines, String for table types. The `std::string`
  by-value params at cc:117–:119 are ABI-pinned (cppcheck suppress comments pin them) — do not
  port them as &str thinking the C signature says refs.
- **R4 statics:** this TU has NONE; its "global" behavior comes from get_file_config()'s two
  singletons (SnortConfig::get_conf + InspectorManager). Harness null-toggle for F6/G3 must
  restore the armed state before later vectors read the table (declaration-order teardown,
  donor rule).
- **R5 line-cite drift:** Rust doc comments cite file_config.h lines from an older snapshot
  (trace_type ":71" vs actual h:69; "72-74" vs :70–:71; get_rule_from_id "70-74"/cc:63 vs
  actual cc:64). Ground-truth cites in THIS plan win at fe29cbe; PORT child refreshes numbers
  only in comments it already touches (no drive-by renumbers).
- **R6 free-vs-member file_type_name collision:** same name, different null behavior ("NA" vs
  compile-time no null) — file_lib.rs:2766–:2772 already distinguishes; vectors F5/F6 vs T*
  arms must not cross-wire.
- **R7 M3 bitset arm may need magic-db fixtures** (get_magic_rule_ids_from_type hits depend on
  FileIdentifier internals, fid row's turf) — fall back to the miss/empty arm + M4 reset pin
  rather than faking table state; check fid_harness vectors.txt first.

## 10. Session ritual

Read-only on snort3-src; no commit in snort3-rust; scratch probes under
/opt/data/cache/scratch; build via `bash build.sh` in the harness dir; vectors.txt is the
oracle — harness runs first (C truth), PORT transcribes against pinned numerals only, never
re-derives from memory.
