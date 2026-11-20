# flog_harness PLAN — row 17z: file_api/file_log.cc (the file-log Inspector TU: FILE_VERDICT LogHandler -> TextLog lines into file.log + the FileLogModule/InspectApi record; NO .h; probe-vectors-only)

Donor: `tools/fsvc_harness` (row 17y, freshest; NEXT.md:91 names it "the NEW
donor for the remaining file_api rows (17z+)"). The entire cp/objs/graft/
shim/gate machinery stays donor VERBATIM (retire rule); deltas marked
NEW17z. Ground truth `/opt/data/snort3-src` @ `fe29cbe` (READ-ONLY).
Port repo `/opt/data/snort3-rust` @ `3093f5e` (row 17y landed).
NEXT.md :108-:130 is the row-17z milestone block; this PLAN re-measured
every claim it makes (all numbers below are THIS recon's own greps).

**EXISTENCE FIRST (re-verified this pass, `ls -la src/file_api/`)**:
`file_log` is a SINGLE-TU row — ONLY `src/file_api/file_log.cc` exists
(**329 L**, 8334 B; NO `file_log.h` — the full file_api/ listing shows no
such file; CMakeLists.txt:30 carries `file_log.cc` with no `.h` twin).
`grep -c 'TEST_CASE' file_log.cc` = 0, `grep -c 'UNIT_TEST' file_log.cc`
= 0 (measured). Donor `grep -n 'file_log' tools/fsvc_harness/build.sh` =
**0 hits** — the row TU is NOT in the donor cp braces (:96) nor the objs
loop (:464). `grep -c 'Peg' tools/fsvc_harness/stubs.cc` = **0** — no
Module/PegInfo witness exists anywhere in the donor closure today.

---

## 0. SCRATCH COMPILE + nm RESIDUE CLASSIFICATION (the backbone — REAL run, this recon; 17w/17x/17y method)

Scratch: `/opt/data/cache/scratch/row17z` — fsvc `copy/` tree HARDLINKED
(`cp -al`), donor gate/probe objs reused untouched, then:

1. **cp deltas (row include closure + the text_log real TU)**:
   `src/log/{text_log.h,text_log.cc,log.h}` -> `copy/log/` (the donor
   carries ONLY `log_errors.h/log_stats.h/messages.h` — build.sh:125;
   `text_log.cc:45` includes `"log.h"`, `main/thread.h` already cp'd at
   build.sh:112). `src/file_api/file_log.cc` -> `copy/file_api/`.
   REAL-cp candidate #2: `src/framework/{module.cc,module.h}` ->
   `copy/framework/`, which drags `utils/stats.h` (:28) and (via it)
   `main/stats_output_format.h` (:31) — both cp'd, compile clean.
2. **flowz/flow_fwd.h graft delta (NEW17z)**: witness `Flow` gains
   `uint16_t client_port / server_port` — file_log.cc:163-164 read
   `f->client_port/f->server_port` (REAL flow.h:586-587; the donor
   witness at build.sh:241-245 only carries the ip/group/key members).
3. **snort_config.h shim delta (NEW17z)**: shim gains
   `#include "framework/inspector.h"` — REAL `main/snort_config.h:35`
   includes it; file_log.cc:202 `class FileLog : public Inspector` only
   reaches `Inspector` through that chain (the donor shim cut it; every
   donor TU compiled without it, so this is the ONE shim edit, and the
   step-6 full-tree `ld -r` re-proves zero regressions).

**COMPILE RESULT (real, measured)**: `g++ -std=c++17 -O0 -w` (donor
GXX, build.sh:454) produces `file_log.o` VERBATIM (no grafts/seds/excisions
fire — 0 UT fragments), plus `text_log.o` and `module.o` from their real
TUs. `nm -u --demangle file_log.o | grep ' U ' | sort -u` = **64 U entries**:

| class | count | members (cites to defining object) |
|---|---|---|
| REAL-OBJ (already in fsvc tree) | **13** | `file_type_name(abi:cxx11)` <= file_config.o (def file_config.cc:80); `FileContext::get_UTF8_fname` <= file_lib.o (decl file_lib.h:193); `FileFlows::get_file_flows/get_current_file_context` <= file_flows.o (real row-17q TU, decls file_flows.h:68/:71); `FileInfo::{get_file_name,get_file_sig_sha256,get_file_size,get_file_type,sha_to_string}` <= file_lib.o (decls file_lib.h:57/:81/:82/:193-area); `SfIp::ntop` <= sf_ip.o; `packet_gettimeofday` <= packet_time.o (real cp, build.sh:115); `ts_print` <= util.o (util.h:122); `sin_file_flow` <= file_inspect.o (**D** at file_inspect.cc:175 — the extern at file_log.cc:322 resolves for free) |
| RESIDENT STUB (stubs.cc witnesses already present) | **7** | `ConfigLogger::log_flag` (stubs.cc:549); `Inspector::{Inspector,~Inspector,get_buf,get_splitter,likes}` + `typeinfo for snort::Inspector` (stubs.cc:485/:495/:502/:503/:504; the typeinfo rides the stub TU's key function) |
| NEW-app (needs NEW witness or real cp THIS row) | **16** | `TextLog_{Init,Print,Putc,Term,Write}` x5 (text_log.h:51/:58/:55/:53 + the `TextLog_Puts` INLINE at text_log.h:74 lowers to `TextLog_Write` — 5, not 6); `Module::{ctor,get_global_count,init_stats,main_accumulate_stats,reset_stats,show_interval_stats,show_stats,sum_stats}` x8 (file_log.cc:244/:247-:251 + the base-class plumbing the FileLogModule ctor emits); `DataBus::subscribe` x1 (file_log.cc:212 — donor stubs.cc has `publish` :268, `get_id` :306, `MPDataBus::subscribe` :345 but grep-0 plain `DataBus::subscribe`, matching NEXT.md:125); `vtable/typeinfo for snort::Module` x2 |
| libstdc++/libc plumbing | **28** | 26 `std::`/`__cxa`/`operator`/`_Unwind`/`isprint`/`gettimeofday`/`strcmp`/`strlen` + `vtable for __cxxabiv1::{__class_type_info,__si_class_type_info}` x2 (libsupc++) |

**Real-cp evaluations (residue-proof, snort_protocols:92 precedent style):**
- **`log/text_log.cc` -> REAL cp RECOMMENDED**: its OWN residue is
  **30 U = 3 REAL-OBJ (`SnortSnprintf` <= util_cstring.o,
  `snort_strdup`/`get_error` <= util.o) + 5 RESIDENT-STUB
  (`ErrorMessage` stubs.cc:125, `FatalError` :135, `get_thread_type` :191,
  `get_instance_file` :192, `get_main_file` :193) + 22 libc/plumbing +
  ZERO NEW-app**. It closes ALL FIVE TextLog NEW entries of the row .o
  without a single new witness body — strictly better than 5 witnesses
  (and the textlog_harness precedent already compiles it verbatim,
  textlog_harness/build.sh:16/:138). ONE guard: do NOT also cp
  `log/messages.cc` (its real bodies would collide with the ErrorMessage/
  FatalError stubs — the rules_harness lineage kept messages.cc out for
  exactly this reason).
- **`framework/module.cc` -> REAL cp RECOMMENDED**: compiles clean (with
  the two header cps, step 1) and its residue is **32 U = 0 real +
  2 RESIDENT-STUB (`ThreadConfig::get_instance_max`, `get_instance_id`)
  + 30 plumbing** — ZERO app NEW. It defines **22 `T snort::Module::`
  methods + `V vtable/typeinfo for snort::Module`** (module.o nm), closing
  8 Module U entries + the vtable/typeinfo pair for free. Strong-def
  collision scan vs the whole donor tree (`nm --defined-only`, T/B/D/V):
  **ZERO collisions** (the 167 name hits are all W/r/n weak+mergeable
  constants like `INVALID_PROTOCOL_ID`/`ip::*` — only `DW.ref.__gxx_personality_v0`
  repeats, weak). Its own residue then exposes exactly ONE app entry:
  `show_stats(const PegCount*, const PegInfo*, unsigned, const char*)`
  (utils/stats.cc:458/:467) — see witness W2. `utils/stats.cc` itself is
  NOT a cp candidate: its include list (:32-:57: detection_engine,
  sfthreshold, memory_module, module_manager, plugin_manager, active,
  sfdaq, trough, profiler_impl, stats/output_json, stats/output_text) is
  the stats monolith — the 2 `show_stats` overloads get inert witnesses.
- **Optional `time/packet_time.cc`**: NOT needed — already a real cp
  (build.sh:464 objs loop carries `packet_time`), `packet_gettimeofday`
  resolved REAL-OBJ above.

**FULL-LINK DUP-SYMBOL PRE-PROOF (R5, the strongest pin)**: incremental
`ld -r` over `{fsvc tree objs (minus *_ut.o/_probe.o)} + text_log.o +
module.o + file_log.o + stubs.o + probe.o` exits **0 — ZERO dup-symbol
errors** (scratch `ld_err.txt` empty). Post-merge app residue (mangled
comm-diff vs nothing, i.e. what the final link still needs): exactly
`show_stats(ulong const*, PegInfo const*, unsigned, char const*)` +
`snort::DataBus::subscribe(...)` — plus the OpenSSL `EVP_*` set which the
donor already answers by linking `$LIBCRYPTO` (build.sh:77/:801). The
`DataHandler` vtable/typeinfo emitted as W/V into file_log.o (Itanium key
at data_bus.h:83) does NOT collide: `file_cache_share.o`/`file_inspect.o`
already define `_ZTVN5snort11DataHandlerE` (the merged `combined.o` shows
exactly one V def); `sin_file` itself (file_log.cc:324, NEW `D`) grep-hits
0 in stubs.cc AND in every tree .o — first and only definition.

**GATE REPRODUCIBLE AT THE 17z SHAPE (claimed, to re-pin in session)**:
the three new .o's are link-additive only (zero dup, zero ctor-observed
behavior — the row TUs' `__static_initialization_and_destruction_0` touch
only TU-private statics, file_log.o `b` list below); donor gate stays
byte-ident **md5 `4826fc2233044a2d5429413faf0ae1af`** ("All tests passed
(114 assertions in 22 test cases)", gate.txt tail, re-measured this pass)
— gate delta ZERO by construction, same claim pattern as 17y PLAN 0.6.

---

## 1. Verbatim symbol inventory (file_log.cc, 329 L, all cites fe29cbe)

**File-scope statics (all TU-internal — hygiene pin like fsvc build.sh:779):**
| line | symbol | notes |
|---|---|---|
| :38 | `static const char* s_name = "file_log"` | module name |
| :39 | `static const char* f_name = "file.log"` | TextLog_Init target (cc:69) |
| :40 | `static const char* s_help` | module help |
| :53 | `static THREAD_LOCAL FileLogStats fl_stats` | 1x PegCount `total_events`; THREAD_LOCAL macro snort_types.h:71-73 (`USE_THREAD_LOCAL` undefined in copy/config.h -> `__thread`) |
| :55-:59 | `static const PegInfo fl_pegs[]` | `{SUM,"total_events","total file events"}` + END terminator |
| :65 | `static THREAD_LOCAL TextLog* tlog` | the fsvc-PLAN "thread_local tlog" — populated only via `dl_tinit` |
| :230-:239 | `static const Parameter fl_params[]` | log_pkt_time (PT_BOOL, default "true"), log_sys_time (PT_BOOL, default "false") |
| :294-:320 | `static const InspectApi fl_api` | IT_PASSIVE, PROTO_BIT__NONE, tinit/term = dl_tinit/dl_tterm, ctor/dtor = fl_ctor/fl_dtor |

**Structs/classes (complete):**
- `struct FileLogConfig { bool log_sys_time=false; bool log_pkt_time=true; }` :42-:46 — defaults matter: pkt-time ON, sys-time OFF.
- `struct FileLogStats { PegCount total_events; }` :48-:51.
- `class LogHandler : public DataHandler` :81-:92: ctor `DataHandler(s_name)` :84; `handle(DataEvent&, Flow*) override` :87; priv `FileLogConfig config` :90; **local** `static void log_file_name(TextLog*, FileContext*)` :91 (private static -> `T LogHandler::log_file_name`, the row .o's first T, scratch `nm --defined-only`).
- `class FileLog : public Inspector` :202-:218: ctor :205; `show(const SnortConfig*) const override` :208/:220-:224 (two `ConfigLogger::log_flag` calls :222-:223); `configure(SnortConfig*) override` :210-:214 (one-line body: `DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FILE_VERDICT, new LogHandler(config))` :212 — `intrinsic_pub_key` is a namespace-scope `const PubKey` at pub_sub/intrinsic_event_ids.h:69 (const => internal linkage, TU-local copy: scratch file_log.o residue carries NO U entry for it; the header is already cp'd, build.sh:97); the only residue is the subscribe call itself (witness W1)).
- `class FileLogModule : public Module` :241-:260: ctor `Module(s_name, s_help, fl_params)` :244; `get_pegs -> fl_pegs` :247-:248; `get_counts -> (PegCount*)&fl_stats` :250-:251; `set()` decl :253 body :262-:271 (two-arm ladder `log_pkt_time`/`log_sys_time`, `v.get_bool()`, return true); `get_usage -> INSPECT` :255-:256; `public: FileLogConfig config` :259 (shared by fl_ctor:286).

**Free functions (all TU-static except the exports):** `dl_tinit` :67-:70 (`TextLog_Init(f_name, 64*K_BYTES, 1*M_BYTES)` — K/M_BYTES text_log.h:41-:42), `dl_tterm` :72-:75 (`TextLog_Term(tlog)`), `mod_ctor` :277, `mod_dtor` :280, `fl_ctor` :283-:287, `fl_dtor` :289-:292.

**Linkage exports:** `extern const BaseApi* sin_file_flow;` :322 (resolves file_inspect.cc:175) and `const BaseApi* sin_file[] = { &fl_api.base, sin_file_flow, nullptr }` :324-:329 — THE row's only non-static data export.

**`LogHandler::handle` emission order (the oracle skeleton, cc:140-:196):**
opt sys-time arm (`gettimeofday` :145 + `ts_print` :147) -> opt pkt-time arm
(`packet_gettimeofday` :155 + `ts_print` :157; both into `char[TIMEBUF_SIZE]`,
util.h:67 = 27) -> `" %s:%d -> %s:%d, "` ip/port pair :163-:164
(`SfIpString ip_str` reuse across two calls — the second `ntop` overwrites the
same buffer, pin it) -> `FileFlows::get_file_flows(f)` :166 null-early-return
-> `get_current_file_context()` :171 null-early-return -> `log_file_name`
:176 -> `"[Verdict: %s] "` `VerdictName[file->verdict]` :178 (global table
file_lib.h:38-39: `{"Unknown","Log","Stop","Block","Reset","Pending",
"Stop Capture","INVALID"}` — NOT a row symbol) -> `"[Type: %s] "`
`file_type_name(...)` :180-:183 (FREE global, file_config.cc:80) ->
conditional `"[SHA: %s] "` via `sha_to_string` :185-:187 -> conditional
`"[Size: %llu] "` :189-:191 -> `"\n"` :193 -> `fl_stats.total_events++` :195.

**`LogHandler::log_file_name` sanitizer (the format quirk to freeze,
cc:94-:138):** early-return on empty name; `get_UTF8_fname(&fname_len)`
:102 with `outbuf != nullptr ? outbuf : name.c_str()` :103; emits
`[Name: "` + per-char: printable -> `TextLog_Putc` :113; unprintable RUN
-> `|` then per byte `%02X` FIRST (no leading space) then `" %02X"` for the
rest of the run (`add_space` quirk :119-:128) then closing `|` :131; tail
`"] "` :135; `snort_free(outbuf)` :136-:137 (util.h:104).

**Row .o ownership (scratch `nm --defined-only file_log.o`, classify):**
`T`: `LogHandler::log_file_name`, `LogHandler::handle`, `FileLogModule::set`,
`FileLog::show`; W: both vtables + ctor/dtor triples (Itanium key-func rule:
the classes' key functions are in-class inline -> dtors emit W in this TU);
`V`: `DW.ref...`; `b` (statics incl. TLS emitted in .tbss/.bss):
`fl_stats`, `tlog`, `fl_params`, `VerdictName`-ref copy (the file_lib.h:38
`b _ZL11VerdictName` — the header-scope `const std::string VerdictName[]`
(file_lib.h:38) gets a TU-LOCAL copy per includer (`_ZL` = internal
linkage): scratch shows it in file_log.o AND already in file_lib.o +
file_flows.o — all internal, zero collision (tree strong-def grep 0);
`t`: the six TU-static api fns + `__tcf_0`.

---

## 2. Donor-closure diff vs tools/fsvc_harness + witness NEW/KEEP/RETIRE table

### 2.1 cp / compile-loop deltas (the ONLY mechanical deltas to the donor script)
1. **:96 cp braces**: append `file_log.cc` (NO .h twin — do not add one;
   the braces pattern would fail on a missing file, which is the
   existence pin). NEW objs-loop `:464` case list: append `file_log`
   (`d=file_api` default — no new case needed) — plain VERBATIM compile.
2. **:125 log braces**: `messages.h,log_errors.h,log_stats.h` -> append
   `text_log.h,text_log.cc,log.h` (the .cc rides the objs loop: append
   `text_log` with `d=log` NEW case — the second dir case after
   `target_based`). messages.cc STAYS OUT (ErrorMessage-collision guard,
   §0). `text_log.h` is compile-only for the row .o; the .cc is the real
   close of the 5 TextLog NEW entries.
3. **NEW dir case `framework`**: cp `module.cc` (module.h already cp'd at
   build.sh:106) + objs-loop append `module`.
4. **Header cps**: `utils/stats.h` and `main/stats_output_format.h`
   (module.cc:28 -> stats.h:31 chain; both header-only, zero link
   contribution — pin: no `show_stats`/`stats::` T-defs appear from them).
5. **flowz/flow_fwd.h graft delta**: `+ uint16_t client_port/server_port`
   (real flow.h:586-:587) — the ONLY flowz change since 17q.
6. **snort_config.h shim delta**: `+#include "framework/inspector.h"`
   (real snort_config.h:35). The full-tree `ld -r` exit-0 (scratch) is
   the regression pin for this edit.
7. **Gate/probe shape**: both links gain `text_log.o module.o file_log.o`
   (`ld -r` exit 0 proves neither link breaks; gate vectors zero-delta by
   construction — the gate never calls the row api).

### 2.2 Witness table (stubs.cc cites; RETIRE vs KEEP vs NEW)
| action | block | why |
|---|---|---|
| RETIRE | **NONE** | `grep -n 'FileLog\|file_log\|TextLog\|Peg' stubs.cc` = 0 hits (measured this pass) — the donor closure never witnessed this row's surface. ZERO retirement; R5 zero-collision re-proved by the scratch `ld -r` exit 0. |
| KEEP | Inspector witness block stubs.cc:485-:510 + `typeinfo` | closes 6 of the row's 7 RESIDENT entries (file_log.cc:202 derives FileLog from Inspector; the vtable keys ride the stub TU). The 17w precedent ("IMGR acquire -> null") still localises gate identity. |
| KEEP | ConfigLogger::log_flag stubs.cc:549 | closes file_log.cc:222-:223 (`show()`). |
| KEEP | main/thread.h witness trio stubs.cc:191-:193 (`get_thread_type/get_instance_file/get_main_file`) + ErrorMessage :125 / FatalError :135 | close `text_log.o`'s ENTIRE 5-entry resident class with ZERO new work (scratch classification). |
| **NEW W1** | `void DataBus::subscribe(const PubKey& key, unsigned eid, DataHandler* h)` — minimal shape: print `WITNESS subscribe key=<module-ish> eid=<FILE_VERDICT id>` + stash the handler pointer in ONE static slot the probe can fire (the probe NEVER runs the real DataBus, file_log.cc:212 is a registration-only call — the row probe calls `handler->handle(evt, &flow)` directly). NEVER cp framework/data_bus.cc (the bus monolith; get_id/publish witnesses already stand at :306/:268). |
| **NEW W2** | `show_stats(const PegCount*, const PegInfo*, unsigned, const char*)` (+ the vector/FILE* overload, utils/stats.h:101-:102) — inert witness print. This is module.o's ONLY app residue (scratch `nm_module.txt`: app residue after tree = exactly `show_stats(...)` + memcpy/memmove). stats.cc never cps (monolith includes list stats.cc:32-:57). |
| NEW W3 (maybe) | none else: the 16-entry NEW-app list collapses exactly — 5 `TextLog_*` (close via REAL text_log.o cp) + 8 Module methods incl. ctor (`Module::Module`, `get_global_count`, `init_stats`, `main_accumulate_stats`, `reset_stats`, `show_interval_stats`, `show_stats`, `sum_stats`) + 2 Module `vtable`/`typeinfo` (all 10 close via REAL module.o cp) + `DataBus::subscribe` (closes via W1); the 2 `__cxxabiv1::{__class,__si_class}_type_info` vtables in the raw 18-entry nm -u list are libsupc++ plumbing answered by libstdc++ at final link (`ld` of the donor already links libstdc++ implicitly). |

Residue-pin template (mirror 17w/17x/17y pins, land `nm_flog.txt`):
`file_log.o` U-total `-eq 64`; app-count `-eq 36` (13 real + 7 resident +
16 NEW); comm-diff vs link-member defined set: after text_log/module
witnesses land, surviving flog entries == 28 plumbing + 0 app (the two
remaining app entries, `DataBus::subscribe` + the row's own none, close
via W1). Self-checks: `grep -c TEST_CASE copy/file_api/file_log.cc` = 0,
`grep -c UNIT_TEST` = 0, and `test $(nm -C stubs.o | grep -cE ' T
(snort::)?(TextLog_|Module::|FileLog))' -eq 0` (R5 guard for the future).

---

## 3. Rust landing per symbol (grep-verified sites; REAL-in-17z vs stays-seam)

`grep -rn 'FileLog\|file_log\|TextLog' src/ tests/` (this recon, Rust side):
the ONLY current hits are the `file_log_event` TRAIT-SEAM cluster + two
forward-reference comments — **the LogHandler rendering itself is UNPORTED
everywhere**:

| C symbol (cite) | Rust status | verdict for 17z |
|---|---|---|
| `TextLog_{Init,Term,Print,Putc,Write,Flush,Quote...}` (text_log.h:51-:62) | **LANDED** `src/log/text_log.rs` 422 L: `TextLog` struct :54, `text_log_init` :161, `text_log_term` :206, `flush` :251, `putc` :279, `write` :302, `print` :343 (variadic-lite `Arg`), `quote` :380, `avail`/`reset` :71/:76; `Clock = Box<dyn FnMut() -> u64>` :40 (the time-injection seam) | **zero Rust edit**; the real C TU now links in the harness and CONFIRMS the twin (real-TU-parity-as-witness, the 17y snort_protocols ruling). |
| `LogHandler::log_file_name` sanitizer (cc:94-:138) | **LANDED-SIBLING, WRONG CALL SITE**: file_lib.rs:2319-:2326 `log_file_name`-equivalent rides `log_file_event_sink` (file_lib.rs:~2305) through the printable sanitizer for the FileCache event path (pub_sub/file_events.cc:54 twin, not the file.log renderer); the `%02X`-run quirk has no dedicated twin | **PORT (probe-grade)** or pin as seam: the quirk (`|XX XX|`, first-byte-no-space) must be frozen somewhere; cheapest = file_lib.rs-adjacent small fn + file-scope unit test, NOT a new trait. |
| `LogHandler::handle` emit order (cc:140-:196) | NOT landed (grep 0) | **port-lite** mirroring FileServiceLite (17x pattern, fsvc PLAN §3:404): `FileLogLite { log_sys_time, log_pkt_time }` + `handle` producing the exact line into a `TextLog`-equivalent sink; verdict/type/sha/size getters ALL land already: `sha_to_string` file_lib.rs:590 (UPPERCASE hex, matches conv[] "012345678ABCDEF" file_lib.cc — pin case), `get_UTF8_fname` file_lib.rs:1781, `file_type_name` file_lib.rs:915 (free-global variant seam file_lib.rs:3336-:3344 `conf ? ... : "NA"`), `VerdictName` table NOT landed -> port as `const [&str;8]` pinning file_lib.h:38-39 verbatim. |
| `file_log_event` TRAIT SEAM consumers | file_cache.rs:532 (`NoopFileCacheEventSink`, stays no-op — mirrors the bus queue comment file_cache_share.rs:578); file_lib.rs:2314 forwarder; tests implement stubs fcache_parity_test.rs:346, fflows_parity_test.rs:256, fctx_parity_test.rs:321 (1 occurrence each, measured) | **stays seam** — these are the FileService/FileFlows/file_cache consumers NEXT.md asked about: 17z does NOT wire file.log rendering into them (the C side's FileLog is an optional inspector riding the bus; the Rust seams keep no-op defaults). |
| `FileLogConfig` params + `set` ladder (cc:230-:239/:262-:271) | `parameter.rs`/`value.rs` landed (framework/), but no FileLog twin | **port** the 2-bool ladder in FileLogLite (probes V2); params table itself is a frozen-const pin. |
| `sin_file[]` registry (cc:324-:329) + `extern sin_file_flow` | `SIN_FILE_FLOW: InspectApiRecord` already at file_inspect.rs:515 (:511-:512 comments name "the 18+ file_log row" as consumer) | **stays doc-seam**: add file_inspect.rs comment pinning `sin_file[] = {fl_api.base, sin_file_flow, nullptr}` at 17z, no new record. |
| `ConfigLogger::log_flag` show-pair (cc:222-:223) | **LANDED** messages.rs:439-:454 (`ConfigLogger; log_flag`) | zero edit. |
| `ts_print` + `TIMEBUF_SIZE` (util.h:67/:122; call cc:147/:157) | **LANDED** src/utils/util.rs:9 (`TIMEBUF_SIZE 27`), `TimeCfg` :60, `ts_print` :86, `ts_print_mmdf` :129, 6 inline tests (:287 `ts_print_formats`) | zero edit; harness risk R1 is C-side only. |
| `packet_gettimeofday` (packet_time.h:29) + sys `gettimeofday` (cc:145) | Rust models it as injected `Clock`/sinks (file_cache.rs:648-:686 comment: "packet_time_update semantics stay" seam) | **stays seam** (Clock injection is the Rust idiom). |
| `fl_stats.total_events` + `fl_pegs` (cc:50-:59/:195) | `PegCount/PegInfo` landed framework/counts.rs:20/:6-:12 | seam-with-pin: FileLogLite carries one `total_events: PegCount` (the 17s thread-local question -> §5 R2). |
| `fl_api` InspectApi record (cc:294-:320) | record-shape precedent file_inspect.rs:515 `InspectApiRecord` | port as one const-record pin (IT_PASSIVE/PROTO_BIT__NONE/tinit-slot names), OR keep as probe-side C-frozen vector; record fields ride vectors.txt V1. |

---

## 4. Frozen-oracle audit (tests/ files, grep-counted THIS recon)

| file | size | asserts / `#[test]` | verdict |
|---|---|---|---|
| tests/textlog_parity_test.rs | 489 L | 1 `#[test]`, whole-transcript replay `include_str!` of tools/textlog_harness/vectors.txt (:468; vectors 87 L md5 `ffcf10a1ac7ef10c8d3626a380dc2575`, fake clock :102) | **UNTOUCHED** — the TextLog twin oracle; the row's real text_log.o cp must NOT re-run/fuzz this harness. |
| tests/log_parity_test.rs | 430 L | 3 asserts / 1 test | untouched (messages twin). |
| tests/fcache_parity_test.rs | 1653 L | 28 asserts / 8 tests; 1 file_log_event seam impl :346 | UNTOUCHED (stays no-op default). |
| tests/fflows_parity_test.rs | 1431 L | 28 asserts / 9 tests; 1 seam :256 | UNTOUCHED. |
| tests/fctx_parity_test.rs | 2471 L | 25 asserts / 4 tests; 1 seam :321 | UNTOUCHED. |
| tests/util_unfold*_test.rs + src/utils/util.rs inline | — | 6 inline tests incl. `ts_print_formats` util.rs:287 | UNTOUCHED (R1 pins ride it). |
| tools/fsvc_harness/{vectors,gate}.txt | 64 L md5 `54864705dd654a18585960a13a853baf`; gate 114/22 md5 `4826fc2233044a2d5429413faf0ae1af` (both re-measured) | UNTOUCHED | new `tools/flog_harness/vectors.txt` is the ONLY new oracle (fresh FLOG-PROBE rows; never edit the fsvc one). |

**No existing oracle needs an edit for 17z** — the row is pure landing
(real .o's join the harness; Rust twins already answer). New vectors file
covers: param defaults (cc:232-:236 "true"/"false"), the handle line shape
under a PINNED packet time, the name-sanitizer run quirk x3 (empty name,
pure-ASCII, mixed run), VerdictName index walk x8, SHA presence/absence x2,
Size skip-at-0 x1, total_events counter x1.

## 5. Risks (cites)

- **R1 TIME DETERMINISM (the row's central risk)**: handle() pulls TWO
  clock sources — wall `gettimeofday` (cc:145) and `packet_gettimeofday`
  (cc:155, real `packet_time.o`, THREAD_LOCAL `s_recent_packet` at
  packet_time.cc:40-:41). C-side MUST pin: probe calls `packet_time_update
  (&fixed_tv)` (packet_time.h:30) before each handle and leaves
  `log_sys_time=false` (cc:44 default) for determinism, with ONE sys-time
  arm behind a fixed TZ — `ts_print` reads `SnortConfig::get_conf()->thiszone`
  + `output_use_utc()` (util.cc body; shim SnortConfig carries neither
  today -> shim members needed, or freeze vectors only with pkt_time). Time
  source PIN decision mirrors the landed Rust pattern: `Clock` injection
  (text_log.rs:40).
- **R2 THREAD_LOCAL**: `fl_stats` (cc:53) and `tlog` (cc:65) are TLS; with
  USE_THREAD_LOCAL undefined in copy/config.h they are `__thread`
  (snort_types.h:71-:73) — probe is single-thread, so the pointer slots are
  effectively global; do NOT cp main/thread.cc (17r rule) — `dl_tinit`
  writes `tlog` via the REAL TextLog_Init over the stubbed
  get_main_file (stubs.cc:193 returns the bare name -> probe writes
  `file.log` in CWD; clean-up between probe phases like textlog harness
  dump/clean arms), and TLS dtor interactions stay 1-thread-only. From 17s
  lineage: stats TLS arms already exist (stubs.cc:191-:196 file_trace
  precedent).
- **R3 FORMATTER PINS**: SHA hex **UPPERCASE** (file_lib.cc conv[], Rust
  twin file_lib.rs:590 — case-pin the vectors); name-sanitizer `|XX XX|`
  first-byte spacing quirk (cc:119-:128); `TIMEBUF_SIZE 27` (util.h:67);
  ip/port pair reuses ONE `SfIpString` (cc:162-:164).
- **R4 bus never runs**: `configure()` only REGISTERS (cc:212, W1 witness);
  the probe must invoke the stashed handler directly — never resurrect a
  real DataBus (R5-adjacent: file_lib publish witnesses stay stubs.cc:268-:294).
- **R5 zero-retire guard**: stubs.cc has NO TextLog/Module/FileLog bodies
  today (grep 0 measured); the landmine is re-adding Module witnesses in a
  future frame after module.o goes real — new `nm -C stubs.o | grep -cE '
   T (snort::Module::|snort::TextLog_|snort::DataBus::subscribe)'` pin:
  Module/TextLog stay 0 (real .o's own them), DataBus::subscribe == 1 (W1).
- **R6 messages.cc collision** (§0): real text_log.o + stubs ErrorMessage/
  FatalError coexist ONLY while messages.cc stays uncp'd.
- **R7 libcrypto**: the merged residue shows `EVP_*` (from file_cache's
  real digest helpers) — already answered by `$LIBCRYPTO` (build.sh:77);
  the flog probe link must keep that term (build.sh:801 shape).
- **R8 shim Inspector-chain edit is the ONLY change to shared graft files
  besides flow_fwd ports**: if any donor self-check pins the shim text,
  re-pin (scratch full-tree `ld -r` exit 0 already proves member-level
  safety; gate md5 re-pin in-session).

## 6. Session ritual (mirror fsvc PLAN §6)

build.sh from donor VERBATIM + §2.1 deltas (NEW17z tags) -> compile the
three row TUs VERBATIM -> `nm` pins per §0 (64/30/32 residue counts, the
comm-diffs, the ld -r exit-0 pin) -> stubs.cc + W1/W2 ONLY (zero
retirements) -> fresh probe.cc (V1 record/static sizes incl `k_bytes=1024,
M=1048576` text_log.h:41-:42 -> 65536/1048576 Init args at cc:69; V2
param-default + set-ladder arms; V3 handle x ladder under pinned packet
time x verdict x8; V4 sanitizer x3; V5 SHA/Size skips; V6 counter) ->
vectors.txt fresh, md5-pinned, hygiene `! grep -E '0x[0-9a-f]{6,}'` kept ->
gate UNCHANGED re-assert md5 4826fc22... -> NEXT.md row 17z entry lists:
zero Rust edits REQUIRED (all §3 landings pre-exist; the optional
LogHandler-lite is a follow-up decision, NOT gated by this harness row).
