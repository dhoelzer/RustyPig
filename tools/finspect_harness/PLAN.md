# finspect_harness PLAN — row 17w: file_api/file_inspect.{h,cc} (the inspector-registration TU: configure() arms the REAL FileCache, the ConfigLogger show ladder, the MP-bus subscription, the sin_file_flow API record)

Ground truth: /opt/data/snort3-src @ fe29cbe (READ-ONLY). Port: /opt/data/snort3-rust @ 01adce3.
Donor: tools/fcapi_harness (row 17v; 17p–17v lineage). This PLAN mirrors the fcapi PLAN structure.
Harness dir name: `tools/finspect_harness` — the name is pinned by NEXT.md:117 ("new
`tools/finspect_harness` from the **fcapi** donor"), no reconciliation needed this time.
Line measures re-run fresh at 01adce3: file_inspect.h = 42 lines, file_inspect.cc = 175 lines
(wc -l, this recon), 0 TEST_CASE / 0 UNIT_TEST fragments in BOTH files (grep this recon) —
probe-vectors-only posture, same as 17u/17v.

## 1. Verbatim symbol inventory (all cites at fe29cbe unless marked "fcapi build.sh/stubs.cc")

### file_inspect.h (42 lines) — complete

- Guard FILE_INSPECT_H :21/:41; include `framework/inspector.h` :26 (REAL header already cp'd,
  fcapi build.sh:64). Author Hui Cao :19.
- `class FileInspect : public snort::Inspector` (:28) — an Inspector, not a Module.
  - `FileInspect(class FileIdModule*);` (:31) — ctor takes the FILE_ID module (forward-named class;
    FileIdModule is `class FileIdModule : public snort::Module` file_module.h:46, header ALREADY
    cp'd at fcapi build.sh:54).
  - `~FileInspect() override;` (:32)
  - `void eval(snort::Packet*) override { }` (:33) — INLINE EMPTY eval (the whole point: this
    inspector never inspects packets; IT_PASSIVE at cc:161).
  - `bool configure(snort::SnortConfig*) override;` (:34)
  - `void show(const snort::SnortConfig*) const override;` (:35)
  - `class FileConfig* config;` (:36) — PUBLIC raw pointer member; the 17u LEFT-OPEN target
    (file_config.rs:240-:243, §3.4 below). No private:/protected: anywhere in the header — the
    FIXACC loop (fcapi build.sh:252) does NOT list file_inspect.h and MUST NOT: its
    `assert n >= 1` ("private:") would fire on 0 occurrences.
- `unsigned get_file_adv_pub_id();` (:39) — free function; body in this same .cc (:87-:88);
  ONLY consumer src-wide: file_lib.cc:658
  `DataBus::publish(get_file_adv_pub_id(), FileEventIds::FILE_COMPLETE, file_event, flow);`
  (grep-verified this recon).

### file_inspect.cc (175 lines) — complete

- Includes: config.h ifdef :26-:28; own header :30; `<atomic>` :32; `log/messages.h` :34
  (ConfigLogger decls live there — copy/log/messages.h:63 `class SO_PUBLIC ConfigLogger final`,
  log_flag :70, log_value(long) :90, log_value(unsigned long) :91); `file_cache.h` :36,
  `file_cache_share.h` :37, `file_config.h` :38, `file_flows.h` :39, `file_module.h` :40,
  `file_service.h` :41, `pub_sub/file_events_ids.h` :42. `using namespace snort;` :44.
- `static std::atomic<unsigned> file_adv_pub_id{0};` (:46) — file-local atomic, THE state this row
  owns; Rust already mirrors the readout at file_lib.rs:1058-:1059
  (`/// file_inspect.cc:46 `static std::atomic<unsigned> file_adv_pub_id`` / `pub adv_pub_id: Cell<u32>`).
- `FileInspect::FileInspect(FileIdModule* fm) { fm->load_config(config); }` (:48-:51) — ctor
  OWNS-BY-TRANSFER: `void FileIdModule::load_config(FileConfig*& dst) { dst = fc; fc = nullptr; }`
  (file_module.cc:263-:266; declaration file_module.h:61 — a plain member, NOT virtual).
- `FileInspect::~FileInspect() { if (config) delete config; }` (:53-:57) — single-owner delete
  of the transferred FileConfig (pair with load_config's steal).
- `bool FileInspect::configure(SnortConfig* sc)` (:59-:85):
  - `if (!config) return true;` (:61-:62) — null-config EARLY RETURN arm (probe vector).
  - `FileCache* file_cache = FileService::get_file_cache();` (:64) — inline getter
    (file_service.h:98 `static FileCache* get_file_cache() { return file_cache; }`).
  - `if (file_cache) { file_cache->set_block_timeout(config->file_block_timeout);
    set_lookup_timeout(config->file_lookup_timeout); set_max_files(config->max_files_cached); }`
    (:65-:70) — REAL FileCache setters (file_cache.h:65-:67 `void set_block_timeout(int64_t);` etc.)
    resolve to the REAL file_cache.o (nm: `T FileCache::set_block_timeout(long)`,
    `T set_lookup_timeout`, `T set_max_files` in copy/file_api/file_cache.o this recon).
    Rust twins already ported 17p: file_cache.rs:1169/:1174/:1179
    (`pub fn set_block_timeout/set_lookup_timeout/set_max_files`).
  - `FileService::set_max_file_depth(sc);` (:72) — witness body already present (stubs.cc:469
    `void FileService::set_max_file_depth(const SnortConfig*) { }` — EMPTY; NEXT.md:123 says to
    INSTRUMENT it for this row, e.g. print + g_max_file_depth readout).
  - `file_adv_pub_id = DataBus::get_id(file_adv_pub_key);` (:74) — PubKey
    `file_adv_pub_key { "file_adv_events", FileEventIds::num_ids }` (file_events_ids.h:50;
    FileEventIds::FILE_COMPLETE = 0 then num_ids, file_events_ids.h:44 → events=1).
    `static unsigned get_id(const PubKey&);` data_bus.h:108 (REAL body data_bus.cc:98, NOT in the
    donor — NO DataBus::get_id in fcapi stubs.cc, grep this recon: only the publish family
    :258/:272/:278/:284). NEW witness body REQUIRED (§2 table).
  - `if (sc->mp_dbus) { ... }` (:76-:83):
    `MPSerializeFunc serialize_func = serialize_file_event;` (:78) /
    `MPDeserializeFunc deserialize_func = deserialize_file_event;` (:79) — real bodies
    file_cache_share.cc:44/:63 (REAL TU already in the objs loop, fcapi build.sh:386 — nm shows
    both defined in copy/pub_sub… no: in copy/file_api/file_cache_share.o, verified this recon);
    `MPDataBus::register_event_helpers(file_mp_pub_key, FileMPEvents::FILE_SHARE_SYNC,
    serialize_func, deserialize_func);` (:81, decl mp_data_bus.h:173) +
    `MPDataBus::subscribe(file_mp_pub_key, FileMPEvents::FILE_SHARE_SYNC, new FileCacheShare());`
    (:82, decl mp_data_bus.h:155; `FileCacheShare() : DataHandler(FILE_ID_NAME) {}` inline,
    file_cache_share.h:32; `vtable for snort::FileCacheShare` + DataHandler base W-symbols all
    present in file_cache_share.o — `new FileCacheShare()` LINKS as-is, verified this recon).
    `file_mp_pub_key { "file_mp_events", FileMPEvents::num_ids }` (file_events_ids.h:49;
    events=2 — matches the existing witness print `MPDBUS get_id name=file_mp_events events=2 -> 42`,
    fcapi stubs.cc:298-:299). `sc->mp_dbus` is the EOFCFG-shim member (fcapi build.sh:131
    `bool mp_dbus = false;`), armed via `fcache_set_mp_dbus` (stubs.cc:302).
- `unsigned get_file_adv_pub_id() { return file_adv_pub_id; }` (:87-:88) — REAL definition;
  REPLACES the donor stub (stubs.cc:309, §2).
- `static void file_config_show(const FileConfig* fc)` (:90-:117) — the SHOW LADDER, 18 caption
  sites: 7 `ConfigLogger::log_flag` (:92 enable_type, :95 enable_signature,
  :98 block_timeout_lookup, :101 enable_capture, :114 trace_type, :115 trace_signature,
  :116 trace_stream) + 11 `ConfigLogger::log_value` (:93 type_depth, :96 signature_depth,
  :99 block_timeout, :103 capture_memcap, :104 capture_max_size, :105 capture_min_size,
  :106 capture_block_size, :109 lookup_timeout, :110 max_files_cached, :111 max_files_per_flow,
  :112 show_data_depth). Gating semantics to pin: log_flag RETURNS the flag
  (real body src/log/messages.cc:364-:371), so each `if (log_flag(...))` prints the caption THEN
  conditionally its value(s); :92/:95/:101 gate on FileService enable statics (REAL in stubs at
  :451-:453), :98 on `fc->block_timeout_lookup`, :114-:116 on FileConfig trace members.
  Mixed arg widths REQUIRED: log_value(long) — file_type_depth/file_signature_depth/int fields
  promote — and log_value(unsigned long) — capture_memcap etc.; witness overloads must match the
  declared defaults (copy/log/messages.h:70/:90/:91) or the link fails.
- `void FileInspect::show(const SnortConfig*) const { if (config) file_config_show(config); }`
  (:119-:123) — null-config guard arm (:121).
- Module plumbing (file-static, registered): `mod_ctor() { return new FileIdModule; }`
  (:125-:126 — drags `U FileIdModule::FileIdModule()`; real body file_module.cc:146, module .cc
  NOT compiled — NEXT.md:114); `mod_dtor(Module* m) { delete m; }` (:128-:129);
  `file_init() { FileFlows::init(); }` (:131-:134 — REAL inline body file_flows.h:62-:63
  `{ file_flow_data_id = FlowData::create_flow_data_id(); }`, both already resolved in the donor:
  `U snort::FileFlows::file_flow_data_id` + `U snort::FlowData::create_flow_data_id()` close
  against file_flows.o + real code today);
  `file_ctor(Module* m) { return new FileInspect(static_cast<FileIdModule*>(m)); }` (:136-:140);
  `file_dtor(Inspector* p) { delete p; }` (:142-:145).
- `static const InspectApi file_inspect_api = { { PT_INSPECTOR, sizeof(InspectApi),
  INSAPI_VERSION, 0, API_RESERVED, API_OPTIONS, FILE_ID_NAME, FILE_ID_HELP, mod_ctor, mod_dtor },
  IT_PASSIVE, PROTO_BIT__NONE, nullptr, "file", file_init, nullptr, nullptr /*tinit*/,
  nullptr /*tterm*/, file_ctor, file_dtor, nullptr /*ssn*/, nullptr /*reset*/ };`
  (:147-:173) — FILE_ID_NAME `#define FILE_ID_NAME "file_inspect"` / FILE_ID_HELP
  "configure file inspection" (file_config.h:42/:43, consts landed 17u at file_config.rs:91);
  API_OPTIONS comes from the harness-written framework/api_options.h (fcapi build.sh:87
  `#define API_OPTIONS 0`). The probe reads these BaseApi fields OFF the global.
- `const BaseApi* sin_file_flow = &file_inspect_api.base;` (:175) — NEW global this row lands
  (donor grep-0 this recon; upstream consumer file_log.cc:322
  `extern const BaseApi* sin_file_flow;` feeding `sin_file[]` at file_log.cc:327 — file_log.cc is
  NOT in the closure → no collision either way).

Scratch probe (this recon, /opt/data/cache/scratch/row17w/file_inspect.o compiled against the
fcapi copy/ headers — recompile, don't edit): **49 U entries total = 28 app symbols + 21
libstdc++/libgcc plumbing** (the string cluster, _Unwind_Resume, strlen, operator new/delete,
__cxa_atexit/__dso_handle/__gxx_personality_v0, _GLOBAL_OFFSET_TABLE_, vtable __class_type_info /
__si_class_type_info). Compiles clean `-fsyntax-only` with `-Icopy -Icopy/file_api` (row-local
include of "file_inspect.h" needs the second -I; build.sh cp puts it IN copy/file_api so the
objs-loop compile needs no delta).

## 2. Donor-closure diff vs tools/fcapi_harness + witness table (retire vs NEW, exact stubs.cc cites)

**cp delta: ONE file.** `file_inspect.h` is ALREADY in the donor cp list (fcapi build.sh:54,
VERBATIM braced list — NEXT.md:110 "cp'd (:54)") and stubs.cc includes it (stubs.cc:13).
`file_inspect.cc` has ZERO presence (cp list :54 has no file_inspect.cc; objs loop
fcapi build.sh:386-:391 has no `file_inspect` entry). Delta = append `file_inspect.cc` to the :54
braces + append `file_inspect` to the :386 loop list (it has no flowz/sed dir special-case).
Gates/grafts/shims/catch block: donor VERBATIM (retire rule). ZERO grafts fire on the row TU
(0 UNIT_TEST fragments, 0 TEST_CASE — no FIXLIBUT/FIXCAPUT-style surgery; FIXACC must NOT gain
file_inspect.h, §1 header note).

**Gate delta: ZERO by construction.** Row adds 0 TEST_CASEs → the four-UT-TU gate
(fcapi build.sh:550-:553; duplicate-symbol rule :555) stays the whole gate, tail
`All tests passed (114 assertions in 22 test cases)` (build.sh:584) and md5
`4826fc2233044a2d5429413faf0ae1af` (build.sh:585) carry verbatim — the 17v self-check
pattern (grep TEST_CASE/UNIT_TEST == 0 for the row TU, build.sh:574-:576) repeats for
file_inspect.{h,cc}. gate.txt witness exposure unchanged: today the fcapi gate.txt carries 34
lines of `IMGR acquire -> null` (grep this recon; the InspectorManager witness pair, NOT
FileInspect bodies — no FileInspect print at all in gate.txt, `grep -c FileInspect gate.txt` = 0),
and the post-retire gate link still resolves them through stubs.cc:358-:365 untouched.

**RETIRE (duplicate-symbol landmine — the real .o defines all of these):**

| symbol(s) | donor stub cite | disposition |
|---|---|---|
| FileInspect ctor body + print "FileInspect ctor", arms `config = &g_stub_file_config` | stubs.cc:425-:430 (block comment :420-:424) | RETIRE — real cc:48-:51 takes over. `new FileInspect(nullptr)` at stubs.cc:355 (inside `fcache_set_file_inspector`, :352-:356) MUST re-arm to pass a witness FileIdModule* instead: the REAL ctor dereferences fm (`fm->load_config(config)`, cc:50) — nullptr = segfault (NEXT.md:110: "the real ctor calls load_config, never nullptr-mod"). |
| FileInspect dtor body ("FileInspect dtor") | stubs.cc:431-:434 | RETIRE — real cc:53-:57 `delete config` takes over; pairs with the load_config steal, see R2. |
| FileInspect configure body ("FileInspect configure") | stubs.cc:435 | RETIRE — real cc:59-:85 is the row's LIVE body; every vector arm rides it. |
| FileInspect show body ("FileInspect show") | stubs.cc:436 | RETIRE — real cc:119-:123 + file_config_show :90-:117 is the row's second LIVE body. |
| `get_file_adv_pub_id()` stub (static `g_stub_adv_pub_id = 7`, setter `fcache_set_adv_pub_id`) | stubs.cc:305-:309 (block: comment :305-:306, static :307, setter :308, getter :309) | RETIRE the getter body ONLY (real cc:87-:88 defines it over the cc:46 atomic). Keep the probe arm path via configure(): the DataBus::get_id NEW witness returns the fixed id that lands in the static (NEXT.md:125-:127: "the get_file_adv_pub_id static round-trip (DataBus::get_id witness id -> static -> getter :87)"). `fcache_set_adv_pub_id` cannot survive as-is (would collide with nothing, but becomes meaningless once the static is real; delete it and re-pin the id through configure). NOTE the frozen-vector twins (§4): fcache/fctx/fflows vectors pin `PUB pub=7` (fcache vectors.txt:200, fctx vectors.txt:137/199/225/244, fflows …) — the NEW witness get_id must return 7 to keep harness-family id semantics comparable, but the frozen files are NEVER edited (NEXT.md:86 "committed, NEVER edit"). |

**NOT retired (stay byte-VERBATIM):** stubs.cc:349 `static FileConfig g_stub_file_config;` (the
harness FileConfig; the C++-static hazard is R2), :351 `get_stub_file_inspector`, :371-:376
`fconf_set_file_inspector_null` (the fconf G3 null arm, NEXT.md:86; pointer-swap only),
:358-:365/:364-:365/:377 InspectorManager acquire/get/release witnesses (InspectorManager-row
turf), :451-:469 FileService statics+lifecycles (the row .o CALLS `set_max_file_depth` :469 —
instrument it, don't retire), :391-:416 Inspector base witnesses (they CLOSE 5 of the row .o's U
entries + `typeinfo for snort::Inspector`, measured), :298-:302 MPDataBus get_id/publish pair
(stays; cc:81/:82 need the OTHER two statics, table below).

**NEW witness bodies (the row's app residue that donor objs do NOT close — measured by
`comm` of nm -u file_inspect.o vs nm --defined-only over all fcapi donor .o + stubs.o this recon:
exactly 8 app U unresolved; the other 20 app U close against the existing link):**

| # | symbol (nm -u line) | call site | NEW witness + expected print |
|---|---|---|---|
| 1 | `snort::DataBus::get_id(snort::PubKey const&)` | cc:74 | body in the DataBus block (after :284): mirror the MPDataBus print style (stubs.cc:298-:299) → `DBUS get_id name=file_adv_events events=1 -> 7` (return 7 = the adv id the frozen twins pin; armable). Decl data_bus.h:108; REAL body data_bus.cc:98 NOT linked (fcapi build.sh:103-105 comment: "data_bus.h is REAL here … publish BODIES live in stubs.cc"). |
| 2 | `snort::MPDataBus::register_event_helpers(PubKey const&, unsigned, MPSerializeFunc*&, MPDeserializeFunc*&)` | cc:81 | NEW stub: print `MPDBUS reg_helpers name=file_mp_events evt=1 ser=1 deser=1` (func-ptr liveness only, NO addresses — hygiene gate `! grep -E '0x[0-9a-f]{6,}'`, fcapi build.sh:597). Decl mp_data_bus.h:173. NEXT.md:110 measured grep-0 in stubs.cc. |
| 3 | `snort::MPDataBus::subscribe(PubKey const&, unsigned, DataHandler*)` | cc:82 | NEW stub: print `MPDBUS sub name=file_mp_events evt=1 handler=file_inspect` (read `handler->get_name()`-style only if public; else print the fixed tag). The `new FileCacheShare()` (cc:82) allocates REAL (inline ctor file_cache_share.h:32; vtable W in file_cache_share.o) — witness LEAKS it deliberately (production never unsubscribes; the Rust side documents "never deletes it (perpetual subscriber)", file_cache_share.rs:308-:309). Decl mp_data_bus.h:155. |
| 4 | `snort::ConfigLogger::log_flag(char const*, bool, bool)` | cc:92/:95/:98/:101/:114/:115/:116 | NEW stub mirroring src/log/messages.cc:364-:371 semantics: print `CFGFLAG <caption> enabled|disabled` (word via flag ? …) and RETURN the flag (the `if (log_flag(...))` gate structure depends on the return). Decl copy/log/messages.h:70. |
| 5 | `snort::ConfigLogger::log_value(char const*, long, bool)` | cc:93/:96/:99 (promoted int/long fields) | NEW stub `CFGMEM <caption> <n>` printed right-aligned at the REAL indention = 25 where observable (messages.h private `static constexpr int indention = 25` — FIXACC cannot reach it: messages.h is NOT in the FIXACC loop, and the witness only REPLICATES the formatting, deviating by printing a tag; document). Decl copy/log/messages.h:90. |
| 6 | `snort::ConfigLogger::log_value(char const*, unsigned long, bool)` | cc:103-:106 (capture_memcap/…) | same body family; overload set must match so BOTH nm -u lines close — measure post-build with the fcapi nm-assert recipe (build.sh:577-:583 style: assert the U count drops to plumbing-only). |
| 7 | `FileIdModule::load_config(FileConfig*&)` | cc:50 (via REAL FileInspect ctor) | NEW stub body: `dst = <heap FileConfig>` — see R2: must NOT be &g_stub_file_config (the real dtor deletes; static storage = UB). Fresh `new FileConfig` per arm, once (transfer semantics). Real body file_module.cc:263-:266 (`dst = fc; fc = nullptr;`) — witness replicates the steal from a witness-owned ptr. |
| 8 | `FileIdModule::FileIdModule()` | cc:126 (mod_ctor; and the re-armed :355 toggle if it news a module) | NEW stub body. WARNING (measure at build): file_module.h:46 FileIdModule's base `Module(const char*, const char*, const Parameter*, bool)` is protected (module.h:226) with its body in the uncompiled module.cc — a bare witness ctor body won't compile without also stubbing the Module ctor (or the witness becomes a plain-struct shim and the toggle uses `static_cast<FileIdModule*>` over it, mirroring the NEW17q flowz witness trick, fcapi build.sh:199-:215 precedent). Do NOT compile file_module.cc (NEXT.md:114/:145: drags main/snort.h + managers/module_manager.h + lua). |

**Expected nm after the delta**: `nm -u --demangle copy/file_api/file_inspect.o` | the 8 app
entries close via the table, the other 20 app entries resolve against existing donor objects
(FileCache::set_*3 → real file_cache.o `T`; FileIdentifier::~FileIdentifier → file_identifier.o
`T`; serialize/deserialize_file_event → file_cache_share.o; FileFlows::file_flow_data_id +
FlowData::create_flow_data_id → file_flows.o; FileService statics + set_max_file_depth →
stubs.cc:451-:469; Inspector base 5 + typeinfo Inspector → stubs.cc:391-:416;
vtable FileCacheShare → file_cache_share.o), plus the Inspector::Inspector/~Inspector pair
(stubs.cc:391/:401). Pin in the build.sh like 17v did (build.sh:581-:583 style): the row .o's
`nm -u` count is 49 by construction, and after the witnesses land, the comm-diff against
`nm --defined-only` over the whole donor set (probe recipe in this recon,
/opt/data/cache/scratch/row17w/{rowU.txt,donor_defined.txt}) must leave exactly the 21 plumbing
entries — `test`-assert that.

## 3. Rust landing/seam sites (grep FileInspect|file_inspect src/, this recon, measured) + h:36 closeability

### 3.1 Existing sinks (interim homes today — every cite grep-verified at 01adce3)

| C item (cite) | Rust interim home | verdict for 17w |
|---|---|---|
| `get_file_adv_pub_id` decl/def (h:39, cc:87-:88) + static (cc:46) | file_lib.rs:1046-:1047 doc cites + `FileEnvLite::adv_pub_id: Cell<u32>` (file_lib.rs:1058-:1059, `Cell::new(0)` :1115); consumed at the publish seam file_lib.rs:1650-:1653 (`publish_file_complete(env.adv_pub_id.get(), FILE_EVENT_ID_FILE_COMPLETE)`, trait file_lib.rs:1005/:1011) | CONSOLIDATE: the static+getter is THIS row's symbol — doc-refresh cites stand; the Cell stays on FileEnvLite (the port never had a FileInspect object; see 3.4). New: pin the configure() write path `adv_pub_id = get_id_witness(...) == 7` in the finspect Rust twin. |
| `FileInspect*` handle + `InspectorApi::config` seam | file_cache.rs:489-:493 `/// FileInspect handle seam … pub trait InspectorApi { fn config() -> Rc<RefCell<FileConfigView>>; }`; file_lib.rs:1486 `set_inspector/get_inspector (FileInspect*)` docs; file_lib.rs:1309-:1317 `Pub(crate) config: Option<Rc<RefCell<FileConfigView>>>` / `inspector: Option<Rc<dyn InspectorApi>>` (the two-view deviation comment :1313-:1316 names FileEnvLite::file_config as the full-table side) | KEEP the trait (it models h:36's READ side for file_cache/file_lib). The 17w Rust twin adds the WRITE/owning side as a struct (3.4) — do NOT swap the trait's FileConfigView (17u R9/LEFT-OPEN). |
| IMGR seam (InspectorManager acquire/get/release of the FileInspect) | file_cache.rs:439-:466 `trait InspectorManagerApi` (+ `NullInspectorManager`); call sites file_cache.rs:1275, :1483, :1551; file_lib.rs:1427 (`FileContext::ctor` imgr chain); C truth inspector_manager.cc:1900-:1915 (get via `get_inspector(file_id, Module::GLOBAL)`, acquire adds global ref, null when `!curr_iv`) | LEAVE (InspectorManager row's turf). The C `file_id "file_inspect"` #define (inspector_manager.cc:69) matches FILE_ID_NAME (file_config.rs:91, 17u). |
| MP-bus arms (cc:76-:83) | file_cache_share.rs:306-:310 (subscriber singleton "C `new FileCacheShare()` once (file_inspect.cc:82) and never deletes it (perpetual subscriber)"), :390/:439 serialize/deserialize binding cites (cc:78-:79), :477-:479 seam-closure block ("C producer -> wire -> C subscriber chain, file_inspect.cc:76-:83: register_event_helpers(...) + subscribe(..., new FileCacheShare())"); file_cache.rs:1105-:1111 `mp_wire` WireQueue ("Models the process-wide MPDataBus … (file_inspect.cc:76-:83) — the bus itself stays the unported transport half"), gate `mp_dbus` file_cache.rs:1936 ↔ C :563 | WITNESS/DOC: the row's configure() arms = the SAME seam the 17t/17p closure wired; the Rust twin models register+subscribe as two printed/queued facts, never a real bus. No new Rust transport. |
| configure()'s FileCache trio + set_max_file_depth (cc:64-:72) | setters file_cache.rs:1169/:1174/:1179 (17p); FileConfig fields already on FileConfigLite (file_lib.rs:788, fields fed from super::file_config defaults file_lib.rs:823-:831; block_timeout_lookup file_config.rs:321/:350) | PORT: new `FileInspect::configure(env/cache)` free-fn twin walking null-config → early return; cache-armed trio → real setters; set_max_file_depth seam. All symbols already exist — this row just connects them per the C order cc:61-:72. |
| show()/file_config_show (cc:90-:123) | ABSENT (grep `ConfigLog|config_log|show` src/file_api/*.rs = 0 hits for the logger family) | NEW PORT: a ConfigLogger trait seam (witness-style, NEXT.md:130-:131 "the ConfigLogger trait seam (witness-style)") emitting the 18 captions through an out-collector; ladder shape per §1. |
| FileIdModule::load_config steal (h:61 decl / file_module.cc:263-:266) | ABSENT (file_module row NOT ported) | WITNESS: Rust FileInspect ctor takes an `Option<Rc<RefCell<FileConfigLite>>>` hand-off directly (the steal is C ownership plumbing; deviation sentence cites file_module.cc:263-:266). |
| `sin_file_flow` InspectApi record (cc:147-:175) | ABSENT (grep `sin_file` src/ tests/ = 0) | PORT as consts: PT_INSPECTOR (copy/framework/base_api.h:53 enum order), IT_PASSIVE/PROTO_BIT__NONE/"file"/FILE_ID_NAME/FILE_ID_HELP consts (names already at file_config.rs:91 via 17u). No ctor/dtor fn pointers in Rust — document the record as data-only. |

Landing-site decision: new `src/file_api/file_inspect.rs`, inserted in mod.rs between
`pub mod file_identifier;` (mod.rs:23) and `pub mod file_lib;` (mod.rs:24) — mirrors the
C-underscore alphabetical sort already encoded there. Existing bindings keep compiling via
`pub use` re-exports (17u recipe VERBATIM: "dups -> pub use re-exports, all old bindings
green"); suite total only increases (NEXT.md:65 "cargo test all green (>= 447; never").

### 3.2 FileEnvLite slot audit (measured)

`FileEnvLite` (file_lib.rs:1049) already carries the row's state slots:
`adv_pub_id: Cell<u32>` (:1059, ctor `Cell::new(0)` :1115) and
`file_config: Option<Rc<RefCell<FileConfigLite>>>` (:1082, `None` default :1123) — plus the
get_file_config seam chain file_config.rs:117-:129 (`get_file_config(env) -> env.get_file_config()`,
the C chain get_file_config reads `fi->config` at file_config.cc:89-:100, `const FileInspect* fi =
static_cast<FileInspect*>(InspectorManager::get_file_inspector(sc) … fi ? fi->config : nullptr`
:94-:99) landing on FileEnvLite (17q). fcache_set_file_cache twin = C stubs.cc:475
(FileService::file_cache static :455) — Rust env-side cache handle stays per the file_cache/
file_lib split.

### 3.3 h:36 `FileConfig* config` — 17u LEFT-OPEN closeability (task: can the slot be closed?)

The left-open text (file_config.rs:240-:243): "`file_inspect.h:36` `FileConfig* config` — the
FileInspect member the cc:94-:97 cast reads — stays the `FileEnvLite::file_config` slot (17q)
until the file_inspect row ports the inspector itself." NEXT.md:133-:136: "file_inspect.h:36
`FileConfig* config` IS the named closure target — the FileEnvLite::file_config seam slot can land
here, but only if no 17p/17r pinned vector re-arms."

Class-shape analysis (this recon): in C, h:36 has EXACTLY ONE writer path (ctor via
load_config's steal, cc:50 + file_module.cc:263-:266) and ONE owner-side reader trio:
configure () cc:61-:70, show() :121-:122, plus the EXTERNAL reader file_config.cc:96
(`fi->config`) and the dtor delete :55-:56. Every Rust reader of that member already routes
through `FileEnvLite::file_config` (file_config.rs:122 cites the seam at file_lib.rs:1141+: the
impl FileEnvLite block) or through `InspectorApi::config -> FileConfigView`
(file_cache.rs:489-:493). Closing = land `struct FileInspect { pub config:
Option<Rc<RefCell<FileConfigLite>>> }` in file_inspect.rs whose ctor models the steal
(`config = env.take_file_config()`-style arm), while `FileEnvLite::file_config` keeps serving as
the SINGLE source the G1/G2/G3 arms drive (fconf vectors.txt:12-:14
`G3_null_arm conf_null_noarg=1 conf_null_sc=1 rearmed=1` / `G1_explicit_sc nonnull=1
is_harness_conf=1` / `G2_null_sc_default nonnull=1 is_harness_conf=1`).
VERDICT: **closeable, YES, under one hard constraint**: the close must NOT swap
FileConfigView ↔ FileConfigLite (the duality left open at file_config.rs:244-:247:
"the four-… FileContext.config type duality (two Rc config types coexist at
file_lib.rs:1301-:1309 …) PLAN 8 item 6 keeps it open; swapping … re-arms every pinned
17p/17r vector"). The new FileInspect.config joins on the FileConfigLite side (the full-table
side, matching cc's FileConfig*), leaves the 17p InspectorApi view untouched, and the fconf
G1/G2/G3 replay must stay green unedited.

## 4. Seam closure + replay-suite witness-line impact (grep-enumerated)

New harness = fcapi clone + §2 cp/witness delta. New oracle `tools/finspect_harness/vectors.txt`
(fresh file; NEVER edit after landing). Vector arms per NEXT.md:119-:128, grounded by this
recon's symbol map: V1 null-config early return (cc:61-:62); V2 cache-armed trio ladder
(cc:64-:70 through the REAL FileCache setters — pin the three timeouts/cap read back through the
existing FileCache getters — plus cache-null skip arm via stubs.cc:475 default nullptr);
V3 set_max_file_depth instrumented print (cc:72, stubs.cc:469 body change: print +
g_max_file_depth readout via :568 setter); V4 adv-pub-id static round trip (cc:74 witness id 7
-> static -> getter :87, NEXT.md:126-:127); V5 mp_dbus=true arm: MPDBUS reg_helpers + sub
witnesses fire (cc:81-:82, `fcache_set_mp_dbus` stubs.cc:302) + mp_dbus=false skip arm;
V6 show ladder over all 18 captions with each of the 4 enable arms (cc:90-:117; three
FileService enable statics stubs.cc:451-:453 + block_timeout_lookup config field + the three
trace flags); V7 sin_file_api record consts read off the `sin_file_flow` global (cc:175):
PT_INSPECTOR/IT_PASSIVE/PROTO_BIT__NONE/`file`/name+help + a file_init round trip
(FileFlows::init REAL: file_flow_data_id transitions — id from the stub-side
FlowData::create_flow_data_id arm) and a file_ctor/file_dtor wiring probe against the witness
FileIdModule (never call mod_dtor — the FileIdModule vtable/dtor chain is NOT in the link,
R3); V8 ctor steal semantics (arm witness load_config -> config non-null; show/configure
null arms before that). Probe link recipe: full donor obj set + `file_inspect.o` in both links
(gate objs ride it via the :386 loop; probe link per build.sh:590-:595 shape), catch/gate
blocks byte-VERBATIM, `probe2` pattern optional.

**Witness-line impact on sibling harnesses and their replay suites (enumerate; the rule: sibling
vectors.txt are frozen oracles — NEXT.md:86/:87 "committed, NEVER edit" — so ZERO test edits, but
the line inventory below is the audit trail for "who printed what where"):**

- `tools/fcache_harness/vectors.txt` (278 lines): 66 × "IMGR acquire …" lines, 1 ×
  "FileInspect ctor", `MPDBUS get_id … -> 42` :97 + `MPDBUS publish pub=42 evt=1 …` :98,
  `PUB pub=7 evt=0 len=0` :200 → replayed by tests/fcache_parity_test.rs:57 (`include_str!`).
  Rust witness impls standing in for the OLD stubs: StubInspector :174-:207 (ctor print :189,
  IMGR impl :195-:200), MPDBUS twin :336-:343, adv_pub_id :320/:378/:472.
- `tools/fctx_parity_test` twin: fctx vectors 610 L, 39 × IMGR, 1 × FileInspect ctor (line 1;
  ctor pin also tests/fctx_parity_test.rs:180-:185 StubInspector), 9 × `PUB pub=7`
  (fctx vectors.txt:137/199/225/244/…), adv_pub_id pins :655/:702.
- `tools/fflows_harness/vectors.txt` 146 L, 17 × IMGR, 1 × ctor (line 8); adv_pub_id 7-pin
  :365/:395.
- `tools/filib_harness/vectors.txt` 273 L: 15 × IMGR + 1 × "FileInspect ctor" (line 45,
  followed at :46 by `IMGR acquire -> inspector`); replay tests/filib_parity_test.rs:16
  (whole-transcript include_str!; the ctor line is a witness print there too — after retire
  the FROZEN file still pins it, Rust side unchanged).
- `tools/fcshare_harness/vectors.txt` 25 L, 6 × IMGR, 0 ctor; replay tests/fcshare_parity_test.rs
  :104-:120 ("The C session linked stubs.cc InspectorManager::acquire_file_inspector …
  IMGR acquire -> null").
- `tools/fconf_harness/vectors.txt` 20 L, 0 IMGR, 1 × "FileInspect ctor" AT LINE 1 (probe arms
  `fcache_set_file_inspector(1)` FIRST — fconf probe.cc:65); replay
  tests/fconf_parity_test.rs:110-:116 ("witness FileInspect ctor (stubs.cc :425-:430) PRINTS
  line 1") + :502-:513 position pin.
- `tools/fcapi_harness/vectors.txt` (21 L, md5 a953a5017b74f5d44dbba14df48ac5ea) — 0 FileInspect
  lines; untouched.

CONSEQUENCE for the PORT child: because the retired stub print "FileInspect ctor" was a
POSITION PIN in fconf replay (line 1), the new finspect probe must NOT reuse that literal for
the real-ctor path (the REAL ctor prints nothing; only the witness load_config/DataBus prints
ride). The Rust StubInspector witnesses in the 5 parity tests keep modeling the FROZEN lines —
they are not re-armed; finspect adds its OWN parity test (`tests/finspect_parity_test.rs`
include_str! pattern, suite count strictly increases, NEXT.md:65 ">= 447").

## 5. Risks flagged for HARNESS/PORT children

- **R1 null-mod ctor crash on re-arm**: after the real .cc links, `new FileInspect(nullptr)`
  (stubs.cc:355) dereferences fm at cc:50 → segfault. The toggle must construct over a witness
  FileIdModule (NEXT.md:110 already pins this rule).
- **R2 ownership landmine (delete-on-static)**: the real dtor `delete config` (cc:55-:56) + the
  new witness load_config must NEVER arm `dst = &g_stub_file_config` (the C++-static at
  stubs.cc:349 the retired ctor used, stubs.cc:429) — deleting static storage is UB. Witness must
  hand a heap `new FileConfig` (sizeof 131360 pinned by the 17u CONF line, file_config.rs:237-:239
  "probe CONF line `sizeof_FileConfig=131360`"), single hand-off per probe run (the steal zeroes
  the source, file_module.cc:263-:266 — a second arm after the first steal = config 0 = null arms).
  Also do NOT let the gate link construct+destroy it either (gate prints no FileInspect lines —
  keep it that way, md5 pin).
- **R3 FileIdModule vtable/dtor hole**: `mod_dtor` (`delete m`, cc:128-:129) dispatches through
  the FileIdModule vtable whose home is file_module.{h,cc} — NOT linked (NEXT.md:114/:145). The
  probe NEVER calls mod_dtor and never deletes the witness module (leak it, documented). If
  FileIdModule::FileIdModule()'s witness body won't compile (protected Module ctor,
  module.h:225-:226), use the NEW17q witness-standover precedent (fcapi build.sh:199-:215) —
  measure first, don't pre-graft.
- **R4 ConfigLogger overload fidelity**: nm shows THREE logger U entries (log_flag; long;
  unsigned long) — the witness set must close exactly those (messages.h:70/:90/:91 defaults in
  the copy); wiring the wrong overload = link error, dropping the flag's return value = silently
  wrong show ladder (every cc:92-:101 arm skips its values; compare vs messages.cc:364-:371
  `return flag;`).
- **R5 duplicate-symbol enforcement**: the five retire blocks (stubs.cc:305-:309 getter half,
  :425-:430, :431-:434, :435, :436) MUST all go in one commit — partial retire = "defined twice"
  link break (real .o defines ctor/dtor x2/configure/show/get_file_adv_pub_id).
- **R6 frozen-vector immutability**: §4's inventory exists to prove NO sibling re-arm is needed.
  Never regenerate sibling vectors; the adv-pub id 7 lives on as a NEW witness return value
  (fcache vectors.txt:200 `PUB pub=7` parity), NOT by editing files.
- **R7 two-view duality stays open**: do not let the h:36 closure (3.3) swap FileConfigView ↔
  FileConfigLite (file_config.rs:244-:247; fcapi PLAN R9 carries the same ruling).
- **R8 FIXACC trap on file_inspect.h**: header HAS no private:/protected: (class body all public,
  h:30-:36) — adding it to the FIXACC loop (fcapi build.sh:252 list) fires that loop's
  `assert n >= 1`. NEXT.md:110's "(.h cp'd (:54; also FIXACC :252 …)" parenthetical refers to the
  stubs.cc:13 include context; verify before touching the FIXACC tuple.
- **R9 get_file_config's cast reads the REAL member now**: file_config.cc:94-:99
  `((FileInspect*)InspectorManager::get_file_inspector(sc))->config` — once file_inspect.o is the
  real def, the fconf G1/G2/G3 semantics re-evaluate inside the finspect probe with the REAL
  member; keep the `fconf_set_file_inspector_null` toggle (stubs.cc:371-:376) NOT retired so the
  null arm is still reachable.
- **R10 atomics posture (again)**: cc:46 `std::atomic<unsigned>`; the Rust port keeps plain
  `Cell<u32>` (file_lib.rs:1059) — single-threaded probe ⇒ observationally identical; carry the
  deviation doc when cites refresh (17v R2 precedent, "mutex/atomics not reproduced").
- **R11 eval() is inline-empty in the header (h:33)**: no body, no symbol — the probe cannot
  observe eval through this TU; do NOT invent an eval vector.
- **R12 env facts (don't rediscover, fcapi PLAN R10 carry)**: no `-lcrypto` on this host
  ($LIBCRYPTO absolute .so.3, fcapi build.sh:44); 2-CPU cgroup → serial builds; probe link needs
  the FULL donor obj set (stubs.o drags real TU refs — fcapi PLAN §7 link note).
- **R13 hygiene gate**: no `0x[0-9a-f]{6,}` in vectors.txt (build.sh:597); func-pointers and the
  `new FileCacheShare()` handle print NAMES/flags only.

## 6. Session ritual (mirror fcapi §10)

Read-only on snort3-src; no commit in snort3-rust except this PLAN; scratch probe at
/opt/data/cache/scratch/row17w/ (recompile, don't edit); `bash build.sh` in the harness dir;
vectors.txt is the oracle — harness first, PORT transcribes pinned numerals only; gate tail +
md5 `4826fc2233044a2d5429413faf0ae1af` unchanged-donor invariant; new tracked set
PLAN.md/build.sh/probe.cc/stubs.cc/vectors.txt + .gitignore block (fcapi/copy/, probe, gate,
catch_main.cc, *.o, *.log, gate.txt, nm_residue.txt, nm_inspect.txt — verify with
`git check-ignore` before staging; fcapi block pattern .gitignore:197+).
