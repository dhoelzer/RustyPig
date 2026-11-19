# fcapi_harness PLAN — row 17v: file_api/file_api.{h,cc} (the shared-vocabulary + FilePolicyBase ref-protocol row, probe-vectors-only)

Ground truth: /opt/data/snort3-src @ fe29cbe (READ-ONLY). Port: /opt/data/snort3-rust @ post-17u.
Donor: tools/fconf_harness (row 17u; 17p/17q/17r/17s/17t lineage). This PLAN mirrors fconf PLAN §1–§10.
Naming note: NEXT.md pre-called this harness `fapi_harness`; THIS task pins the directory name
`tools/fcapi_harness` — the docs pass must reconcile the NEXT.md mention, not the other way round.

## 1. Scope definition + size (measured)

- `src/file_api/file_api.h` — 227 lines (6183 B), author Hui Cao 2012 (h:19-20). The header IS the
  vocabulary umbrella of the whole file_api subsystem: 5 feature-word macros, 8 enums, 2 small
  structs, 1 ref-counted policy base, 6 inline helpers, and 4 outbound declarations whose BODIES
  live in OTHER TUs. Includes (:29–:35): `<atomic> <bitset> <cstring> <string>` +
  `main/snort_config.h` + `main/snort_types.h`.
- `src/file_api/file_api.cc` — 43 lines (1496 B), author Ron Dempster 2021 (cc:18 — the three
  FilePolicyBase out-of-line bodies were split out of the header in 2021). Despite the
  "umbrella/factory TU" label on the row: **this TU contains NO factory and ONLY three functions**,
  all FilePolicyBase ref-count protocol (cc:28-:29, :31-:32, :34-:43). `#ifdef HAVE_CONFIG_H`
  config.h (:20-:22), own header (:24), `using namespace snort;` (:26). That is the entire .cc.
- Header consumer map (measured, `grep -rl '#include "file_api/file_api.h"' src`): 8 TUs —
  file_api.cc itself, file_lib.h:24, file_policy.h, mime/file_mime_process.h,
  dce_rpc/dce_smb_utils.cc, ftp_telnet/ftpp_si.h, http_inspect/http_msg_body.h + http_msg_header.h.
  The file_api rows already ported (file_lib/file_cache/file_flows/file_capture/file_config/
  file_identifier) reach it transitively via file_lib.h — which is why this TU has compiled and
  LINKED VERBATIM inside every file_api harness since 17q.

## 2. TEST_CASE inventory (measured)

`grep -c 'TEST_CASE\|UNIT_TEST'`: file_api.h = 0, file_api.cc = 0.
**0 TEST_CASE / 0 `#ifdef UNIT_TEST` fragments → probe-only ground truth row** (same posture as
fcshare 17t / fconf 17u). Gate for the donor copy is UNCHANGED BY CONSTRUCTION (see §7).

## 3. Verbatim symbol inventory (all cites at fe29cbe)

### file_api.h

**Include guard + includes:** FILE_API_H :22/:226; `<atomic>` :29, `<bitset>` :30, `<cstring>` :31,
`<string>` :32, `main/snort_config.h` :34, `main/snort_types.h` :35.

**Feature-word macros (:37–:41):** `ENABLE_FILE_TYPE_IDENTIFICATION 0x1` (:37),
`ENABLE_FILE_SIGNATURE_SHA256 0x2` (:38), `ENABLE_FILE_CAPTURE 0x4` (:39),
`FILE_ALL_ON 0xFFFFFFFF` (:40), `FILE_ALL_OFF 0x00000000` (:41).
MEASURED: these five defines have ZERO consumers anywhere in src (grep-verified) — dead vocabulary
in this snapshot (§9 R5).

**enum FileAction (:43–:48):** `FILE_ACTION_DEFAULT = 0` (:45), `FILE_RESUME_BLOCK` (:46),
`FILE_RESUME_LOG` (:47).

**BOM macros (:50–:51):** `UTF_16_LE_BOM "\xFF\xFE"` (:50), `UTF_16_LE_BOM_LEN 2` (:51).

**enum FileVerdict (:53–:63):** `FILE_VERDICT_UNKNOWN = 0` (:55), `LOG` (:56), `STOP` (:57),
`BLOCK` (:58), `REJECT` (:59), `PENDING` (:60), `STOP_CAPTURE` (:61), `MAX` (:62).

**enum FilePosition (:65–:72):** `SNORT_FILE_POSITION_UNKNOWN` (:67), `SNORT_FILE_START` (:68),
`SNORT_FILE_MIDDLE` (:69), `SNORT_FILE_END` (:70), `SNORT_FILE_FULL` (:71).

**enum FileCaptureState (:74–:81):** `FILE_CAPTURE_SUCCESS = 0` (:76), `FILE_CAPTURE_MIN` (:77
"smaller than file capture min"), `FILE_CAPTURE_MAX` (:78), `FILE_CAPTURE_MEMCAP` (:79),
`FILE_CAPTURE_FAIL` (:80).

**enum FileSigState (:83–:89):** `FILE_SIG_PROCESSING = 0` (:85), `FILE_SIG_DEPTH_FAIL` (:86),
`FILE_SIG_FLUSH` (:87), `FILE_SIG_DONE` (:88).

**enum FileProcessType (:91–:96):** `SNORT_FILE_TYPE_ID` (:93), `SNORT_FILE_SHA256` (:94),
`SNORT_FILE_CAPTURE` (:95). MEASURED: zero consumers in src (the enum is declared and never used
as a parameter type anywhere — file_flows.cc:503 picks `FileDirection`, not this). Dead vocabulary.

**enum FileDirection (:98–:102):** `FILE_DOWNLOAD` (:100), `FILE_UPLOAD` (:101). LIVE:
file_lib.h:137 member default `FILE_DOWNLOAD`, file_flows.cc:503, file_cache.cc:1097.

**enum FileCharEncoding (:104–:108):** `SNORT_CHAR_ENCODING_ASCII` (:106),
`SNORT_CHAR_ENCODING_UTF_16LE` (:107). LIVE: get_character_encoding return (:207-:217),
file_lib.cc:87/:662.

**struct FileState (:110–:114):** `FileCaptureState capture_state;` (:112),
`FileSigState sig_state;` (:113). LIVE: file_lib.h:146 default
`{ FILE_CAPTURE_SUCCESS, FILE_SIG_PROCESSING }`, consumed file_policy.cc:210.

**namespace snort opens :116:**
- `#define FILE_ID_MAX 1024` (:118); `typedef std::bitset<FILE_ID_MAX> FileTypeBitSet;` (:119).
  LIVE: file_identifier.h:98 `FileMeta file_magic_rules[FILE_ID_MAX + 1]`, the M4 reset arm
  (snort::shim, file_config.cc:112).
- `struct FileCacheClearReport (:121–:125):` `uint64_t freed = 0;` (:123),
  `uint64_t remaining = 0;` (:124). LIVE: FileCache::clear() (file_cache.cc:457) return type,
  file_service.h:61.
- Forward decls (:127–:130): `class FileContext;` `class FileInfo;` `class Flow;`
  `struct Packet;`.

**class UserFileDataBase (:132–:142):** defaulting ctor (:135) + virtual dtor (:136),
copy ctor (:137) and copy-assign (:138) DECLARED, private `void copy(const UserFileDataBase&)`
(:141) — and MEASURED FACT: **none of the three copy-path functions has a body anywhere in the
tree** (grep `UserFileDataBase::` → 0 definitions). Any C TU that copies one is a LINK ERROR;
production only ever `new UserFileDataBase` + delete (file_cache.cc:1176, set/get at
file_lib.cc:541/:554, dup check file_cache.cc:426). sizeof = 8 (vptr only; scratch-probe pin
`sizeof_UserFileDataBase=8`, §7 U-block).

**class SO_PUBLIC FilePolicyBase (:144–:172):** the ref-counted policy base.
- `FilePolicyBase();` (:148) — body file_api.cc:28-:29 (`ref_count = 1`).
- `virtual ~FilePolicyBase();` (:149) — body file_api.cc:31-:32 (`assert(!ref_count)`).
- `virtual void policy_check(Flow*, FileInfo*) { }` (:151-:153) — inline EMPTY base body
  ("called when a new flow is queried for the first time").
- `virtual FileVerdict type_lookup(Packet*, FileInfo*) { return FILE_VERDICT_UNKNOWN; }`
  (:155-:157) — inline default ("after file type is known").
- `virtual FileVerdict signature_lookup(Packet*, FileInfo*) { return FILE_VERDICT_UNKNOWN; }`
  (:159-:161) — inline default ("after file signature is complete").
- `virtual void log_file_action(Flow*, FileInfo*, FileAction) { }` (:163) — inline EMPTY.
- `void add_ref() { ++ref_count; }` (:165-:166) — inline.
- `SO_PUBLIC static void delete_file_policy(FilePolicyBase*);` (:168) — body file_api.cc:34-:43.
- `private: std::atomic_uint ref_count;` (:171) — seq_cst `std::atomic<unsigned>` member.
sizeof = 16 (vptr 8 + atomic_uint 4 + tail padding 4; scratch-probe pin `sizeof_FilePolicyBase=16`;
already transcript-pinned indirectly by fctx A_SZ ctx=424 chains that embed policy ptrs).

**Inline FilePosition helpers (:174–:205)** — namespace snort, the ONLY unported LIVE code in
this header; upstream consumer sites (measured): ftpdata_splitter.cc:131/:132, ftp_data.cc:190/
:196/:257/:258, imap.cc:521, smtp.cc:1093, pop.cc:471, file_mime_process.cc:526/:529/:636/:671/
:673/:721/:785/:793/:805/:1039:
- `initFilePosition(FilePosition* position, uint64_t processed_size)` (:174-:179):
  START; if processed_size → MIDDLE.
- `updateFilePosition(FilePosition* position, uint64_t processed_size)` (:181-:187):
  (END|FULL) → START; else if processed_size → MIDDLE; else UNCHANGED (UNKNOWN stays UNKNOWN —
  measured upd_unk0 pos=0).
- `finalFilePosition(FilePosition* position)` (:189-:195): START → FULL; else if != FULL → END.
  QUIRK (measured): UNKNOWN → END (fin_unk pos=3). Pin, never "fix" (§9 R7).
- `isFileStart(FilePosition)` (:197-:200): (START|FULL) == 1 — measured truth table 01001 over
  (UNK,START,MID,END,FULL).
- `isFileEnd(FilePosition)` (:202-:205): (END|FULL) — measured 00011.

**Inline `get_character_encoding(const char* file_name, size_t length)` (:207–:217):**
default ASCII; `length >= UTF_16_LE_BOM_LEN` AND `memcmp(file_name, UTF_16_LE_BOM, 2) == 0` →
UTF_16LE. Measured arms: len<2 → ASCII even with 0xFF; 2 non-BOM bytes → ASCII; BOM+1 → UTF_16LE;
reversed-pair BOM (`\xFE\xF`) → ASCII (`enc_short=0 nonbom=0 bom=1 partial=0`).
LIVE consumers: file_lib.cc:87 (get_UTF8_fname cluster) and file_lib.cc:662.

**Outbound declarations, NO body in this TU (:219–:224)** — the "umbrella" half of the row:
- `SO_PUBLIC uint64_t get_file_processed_size(Flow* flow);` (:219) — body
  **file_service.cc:256** (FileFlows::get_file_flows → get_current_file_context → get_processed_bytes).
- `SO_PUBLIC FilePosition get_file_position(Packet* pkt);` (:220) — body **file_flows.cc:61**
  (is_full_pdu → FULL / is_pdu_start → START / PKT_PDU_TAIL → END / else processed_size ? MIDDLE : UNKNOWN).
- `SO_PUBLIC void set_rule_id_from_type(SnortConfig*, uint64_t id, std::string type,
  std::string file_category, std::string file_version, std::vector<std::string> file_groups);`
  (:221-:222) — body **file_config.cc:117-:127** (row 17u).
- `SO_PUBLIC void get_magic_rule_ids_from_type(const std::string& type,
  const std::string& version, FileTypeBitSet& ids_set, SnortConfig*);` (:223-:224) — body
  **file_config.cc:104-:113** (row 17u). By-value std::string params ABI-pinned by cppcheck
  suppress comments at the .cc site (17u R3).
Do NOT re-port the bodies here: they belong to file_service.cc:256 / file_flows.cc:61 /
file_config.cc:104-:127 and already have ported homes (§5).

### file_api.cc (complete, 43 lines)

- `#ifdef HAVE_CONFIG_H #include "config.h" #endif` (:20-:22) — harness config.h shim already
  resident (donor build.sh:59).
- `#include "file_api/file_api.h"` (:24); `using namespace snort;` (:26).
- `FilePolicyBase::FilePolicyBase() { ref_count = 1; }` (:28-:29) — NOTE: ctor SETS ref to 1,
  it does not default-init then increment (fresh object is held once, like a `new`).
- `FilePolicyBase::~FilePolicyBase() { assert(!ref_count); }` (:31-:32) — destruction is only
  legal at ref 0; harness build has NO -DNDEBUG (donor GXX line `g++ -std=c++17 -O0 -w`), so the
  assert is LIVE (nm residue proves it: `__assert_fail` U).
- `void FilePolicyBase::delete_file_policy(FilePolicyBase* policy)` (:34-:43):
  `if (policy)` (:36 null guard, silent no-op) `{ assert(policy->ref_count); (:38 underflow guard,
  LIVE) unsigned ref = --policy->ref_count; (:39 pre-decrement, read-back) if (!ref) delete policy; (:40-:41) }`.
- Nothing else. No static, no global, no factory.

## 4. `#ifdef UNIT_TEST` fragment table

None (0 occurrences in both files). No ut-only members, no excision recipes for this TU
(the row never needs FIXLIBUT-style surgery — it is byte-VERBATIM in both links).

## 5. Donor-closure diff vs tools/fconf_harness (this recon, exact measurements)

**cp delta: ZERO.** file_api.{h,cc} are already in the fconf cp list
(build.sh:38 VERBATIM, `…file_lib.cc,file_api.h,file_api.cc…`) and in the objs compile loop
(build.sh:370 VERBATIM, first entry `file_api`). The .o that the recon inspected
(`tools/fconf_harness/copy/file_api/file_api.o`) has been linking silently into the probe AND
gate binaries of every file_api harness since 17q/17r.

**nm -u `copy/file_api/file_api.o` (measured): exactly 3 undefined symbols** — the smallest
residue of the entire remaining queue (fconf's own row TU measured 30 U / 6 app in PLAN 3):

|| residue symbol | resolved by |
|---|---|---|
| 1 | `vtable for __cxxabiv1::__class_type_info` | libstdc++ (typeinfo chain of SO_PUBLIC polymorphic base) |
| 2 | `operator delete(void*, unsigned long)` | libstdc++ (sized delete at cc:41) |
| 3 | `__assert_fail` | libc (cc:32/cc:38 asserts, live — no -DNDEBUG) |

**ZERO app-residue.** nm -C also confirms the TU DEFINES everything the header's non-inline parts
promise: FilePolicyBase ctor x2 (T), dtor x3 (T deleting/D0/D1), `delete_file_policy` (T), the 4
virtual defaults (W), vtable/typeinfo (V). Closure verdict: **nothing to close; the donor link
resolves this TU with zero witness work.**

**Scratch-probe closure proof (this recon):** a stand-alone probe
(/opt/data/cache/scratch/row17v/probe_sizes.cc, links against `fconf_harness/stubs.o` + the
donor's full non-UT .o set + `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` ABSOLUTE path — there is
NO `-lcrypto` on this host, NEXT.md env fact) compiles `-fsyntax-only` + `-c` clean against the
donor copy/ headers and its nm -u shows ONLY: FilePolicyBase ctor/dtor/delete_file_policy,
typeinfo, `__si_class_type_info` vtable, operator new/delete, `memcmp`, `printf` — i.e. exactly
the file_api.o + std/libc set. It ran (exit 0) and produced the §7 expected pins.

**stubs.cc delta: ZERO.** The donor already carries the FilePolicyBase witness machinery
(`StubFilePolicy :316-:333` overriding ALL FOUR virtuals with prints, heap `g_stub_policy` +
"static object would hit ~FilePolicyBase's assert(!ref_count) at exit" comment :330-:332,
`fcache_release_stub_policy` :334-:335, `fcache_set_policy_verdicts` :336-:344, and the
`fcache_stub_policy_refs()` ref_count readout :581-:584 enabled by the FIXACC private→public
graft which ALREADY includes `/file_api/file_api.h` (build.sh:230-:236 FIXACC loop line — the
comment there cites "FilePolicyBase::ref_count is read by the policy ref-count witness readout
(fcache_stub_policy_refs); access-only, the arithmetic stays the REAL file_api.cc protocol").
The 17v probe drives the SAME witness class + readout; it adds no symbols.

**Gate delta: ZERO by construction.** 0 TEST_CASE → the four-UT-TU donor gate link
(file_flows_ut + file_mempool_ut + file_cache_ut + file_capture_ut, duplicate-symbol rule at
build.sh:530-:534) stays the whole gate; tail must read
`All tests passed (114 assertions in 22 test cases)` AND the hard `grep -q` +
`md5sum | grep -q '^4826fc2233044a2d5429413faf0ae1af  '` pins carry over unchanged
(build.sh:546-:547).

**Graft carry-overs that touch this row:** FIXACC already rewrites file_api.h private/protected →
public IN THE COPY (access-only; the probe may read `ref_count` directly §7 R-block, and the
donor precedent fcache_stub_policy_refs legitimizes it). The header graft is the ONLY mutation
the row TU's own header undergoes; no sed/excision fires on file_api.{h,cc}.

**Harness-dir hygiene:** tracked set mirrors siblings exactly (fconf tracks PLAN.md, build.sh,
probe.cc, stubs.cc, vectors.txt only; everything else .gitignored at root .gitignore:192-:199).
17v adds an fcapi block: `tools/fcapi_harness/copy/`, `probe`, `probe2`, `gate`,
`catch_main.cc`, `*.o`, `*.log`, `gate.txt`, `nm_residue.txt`, `nm_api.txt`. Verify with
`git check-ignore` BEFORE staging (NEXT.md ritual).

## 6. Rust landing-site analysis (measured, exact lines) + per-function port-vs-witness verdict

Interim homes TODAY (the row was pre-ported piecemeal by rows 17m/17n/17o/17q/17r/17s/17u):

| C item (cite) | Rust interim home (measured grep) | verdict for 17v |
|---|---|---|
| FileAction enum (h:43-:48) | file_cache.rs:308-:310 (u32 consts) | PORT consolidation: move to file_api.rs, `pub use` re-export (17u const-home recipe) |
| FileVerdict enum (h:53-:63) | file_lib.rs:41-:48 | PORT consolidation (values already pinned by filib A_ENUMS vU..vM=0..7) |
| FilePosition enums (h:65-:72) | file_lib.rs:63-:67 | PORT consolidation (filib/fctx/fflows A_ENUM pins) |
| FileCaptureState (h:74-:81) | file_lib.rs:70-:74 | PORT consolidation (fctx A_ENUM cap=0,1,2,3,4) |
| FileSigState (h:83-:89) | file_lib.rs:77-:80 | PORT consolidation (sig=0,1,2,3) |
| FileProcessType (h:91-:96) | ABSENT (grep 0) | PORT consts 0/1/2 ONLY (dead enum this tree — §9 R5; vocabulary completion, no behavior vectors) |
| FileDirection (h:98-:102) | file_lib.rs:83-:84 | PORT consolidation (filib A_ENUMS dl=0 du=1; SZ_DIR=4) |
| FileCharEncoding (h:104-:108) | file_lib.rs:87-:88 | PORT consolidation (enc=0,1) |
| UTF_16_LE_BOM + LEN (h:50-:51) | file_lib.rs:32 BOM_LEN only; byte pair inlined at file_lib.rs:101 | PORT `&[u8; 2] = [0xFF, 0xFE]` const hoisted to vocabulary home |
| ENABLE_FILE_* / FILE_ALL_* (h:37-:41) | ABSENT (grep 0) | PORT consts (dead defines §9 R5; do NOT wire to FileService enable statics — file_service.cc row turf) |
| FILE_ID_MAX (h:118) | file_identifier.rs:21 + mirror file_stats.rs:22 + const FILE_ID_MAX in gate asserts | LEAVE (fid row's turf; file_config.rs:248 already rules "not touched by this row") |
| FileTypeBitSet (h:119) | word form `[u64; FILE_ID_MAX / 64]` (file_config.rs:172 signature) | WITNESS posture: no new bitset type; pin sizeof(FileTypeBitSet)=128 in the C vectors (S-block) and document the array shape; the M-pin chain already closed in 17u |
| FileState (h:110-:114) | file_lib.rs:90-:96 `#[repr(C)] struct FileState` (A_SZ_STATE=8) | PORT consolidation (move struct) |
| FileCacheClearReport (h:121-:125) | file_cache.rs:116-:121 | PORT consolidation (default-0 fields keep C in-class inits; NO derive-temptation — fields already hand-defaulted) |
| UserFileDataBase (h:132-:142) | file_lib.rs:107-:111 opaque trait `UserFileDataBase { as_any }` | KEEP as-is + DOCUMENT deviation (copy ctor/assign/copy() bodies DO NOT EXIST at fe29cbe — porting them = fabrication; C itself is a link error on use; production only news/deletes) |
| FilePolicyBase 4 virtuals (h:151-:163) | file_cache.rs:545-:556 `trait FilePolicyApi` (C empty/UNKNOWN default bodies as Rust defaults) | PORT consolidation: move trait home, `pub use` in file_cache.rs |
| FilePolicyBase ref protocol (h:148/:165/:168/:171 + cc:28-:43) | file_cache.rs:558-:612 `FilePolicyHandle` (PolicyStore{Box<dyn FilePolicyApi>, ref_count: u32}, add_ref :589, delete_file_policy :597 with debug_assert, ref_count() readout, same_store via Rc::ptr_eq) — cited file_api.cc:34 by 17q | PORT consolidation: move handle home (this is the row's actual BODY); deviation docs (atomic->plain u32; Box drop == delete policy) already exist |
| inline initFilePosition (h:174-:179) | ABSENT (grep 0) | PORT: 5 free fns over the u32 FilePosition consts; value-in/value-out (C in/out pointer is a harness artifact of C lacking return tuples — vectors pin both in/out states, §7 P-block) |
| inline updateFilePosition (h:181-:187) | ABSENT | PORT (pin the else-UNCHANGED arm incl. UNKNOWN-stays-UNKNOWN measured upd_unk0=0) |
| inline finalFilePosition (h:189-:195) | ABSENT | PORT (pin UNKNOWN→END, §9 R7) |
| inline isFileStart/isFileEnd (h:197-:205) | ABSENT | PORT (truth tables 01001 / 00011 measured) |
| inline get_character_encoding (h:207-:217) | file_lib.rs:99-:104 (live: file_lib.rs:1269/:1693) | PORT consolidation (move fn; the &[u8] borrow form stands) |
| decl get_file_processed_size (h:219) | file_flows.rs:137 `get_file_processed_size(flows)` (body home file_service.cc:256) | WITNESS/LEAVE: decl-only in this TU, body already ported by 17q — re-porting here would fork the pinned PT/FileEnv ladder |
| decl get_file_position (h:220) | file_flows.rs:163 `get_file_position(p, flows)` (body home file_flows.cc:61) | WITNESS/LEAVE: same rule |
| decl set_rule_id_from_type (h:221-:222) | file_config.rs:199 (body home file_config.cc:117-:127, 17u) | WITNESS/LEAVE |
| decl get_magic_rule_ids_from_type (h:223-:224) | file_config.rs:167 (body home file_config.cc:104-:113, 17u) | WITNESS/LEAVE |

**Landing-site decision:** new `src/file_api/file_api.rs` = canonical vocabulary + policy-base
home (enums, FileState, FileCacheClearReport, inline-helper fns, BOM consts, FilePolicyApi trait +
FilePolicyHandle), re-point file_lib.rs / file_cache.rs interim homes through `pub use` so every
existing binding stays green (17u recipe VERBATIM: "dups -> pub use re-exports, all old bindings
green"). mod.rs gains `pub mod file_api;` (alphabetically before file_cache_share — mirror the
C-underscore sort comment already in mod.rs). LEAVE file_identifier.rs:21 FILE_ID_MAX where it is
(17u explicit ruling). The four outbound decls stay ported at their body homes — the file_api.rs
header carries only doc comments citing h:219-:224 and the body home line, NO duplicate fns.

## 7. Gate plan + PROBE VECTOR PLAN (labeled arms; 0-TEST_CASE TU → probe-only)

Harness posture: **clone the fconf donor; ZERO cp delta, ZERO witness delta, gate md5 must stay
`4826fc2233044a2d5429413faf0ae1af` byte-ident** (row adds no cases; fconf build.sh:546/:547 pins
carry verbatim). New probe.cc = the arms below. Expected pins here were MEASURED this recon by
the scratch probe (§3) — they are expectations, and vectors.txt is written only by build.sh.

**C — CONST/layout line (1 arm):**
`C_sz fpolbase=16 ufd=8 fstate=8 fccr=16 bitset=128 file_id_max=1024` — sizes via the probe's own
`sizeof` (never hand-typed; donor CONF-line style). ufd=8 = vptr-only proof; bitset=128 pins
FILE_ID_MAX/8 * 8.

**E — enum wire values (1 arm, mirrors filib A_ENUMS):**
`E_action 0,1,2 · E_verdict 0,1,2,3,4,5,6,7 · E_pos 0,1,2,3,4 · E_cap 0,1,2,3,4 · E_sig 0,1,2,3 ·
E_ptype 0,1,2 · E_dir 0,1 · E_enc 0,1` (all measured = enumerate order).

**M — macro words (1 arm):** `M_flags 1,2,4 allon=ffffffff alloff=0` — printf %x, no `0x` prefix
hygiene: print as `%x` WITHOUT the `0x` (the hygiene gate forbids `0x[0-9a-f]{6,}` → ffffffff is
8 hex chars AFTER an `=` without 0x; verify with the donor's `! grep -E '0x[0-9a-f]{6,}'`).
BOM byte pin folded here: `bom_len=2 b0=255 b1=254` (decimal bytes, no 0x).

**P — the inline FilePosition ladder (~9 arms; this TU's live semantics; P in the file_api.h
:174-:217 inline region — inline funcs were never gated upstream, probe vectors ARE the truth):**
- `P_init0 pos=1` (init(0) → START), `P_init7 pos=2` (init(nz) → MIDDLE)
- `P_upd_end0 pos=1` (END→START), `P_upd_full9 pos=1` (FULL→START even with data — the reset arm
  precedes the MIDDLE arm, h:183), `P_upd_mid0 pos=2` (UNCHANGED arm), `P_upd_unk0 pos=0`
  (UNCHANGED keeps UNKNOWN — pin vs finalFilePosition §9 R7)
- `P_fin_start pos=4` (START→FULL), `P_fin_mid pos=3` (→END), `P_fin_unk pos=3` (UNKNOWN→END QUIRK)
- `P_isstart 01001` / `P_isend 00011` (five-arm truth tables in enum order UNK,START,MID,END,FULL)

**S — get_character_encoding BOM arms (2 arms):**
`S_enc arms short=0 nonbom=0 bom=1 partial=0` (len<2 with 0xFF / 2-byte non-BOM / BOM+tail /
reversed pair `xFE,xF` — all measured; the memcmp reads EXACTLY 2 bytes only when length>=2,
h:210-:213 — no OOB on len-1 input, pin by construction).
`S_bom_live` optional IF the probe can route one live call through it — NOT recommended:
get_character_encoding's only file_api consumer is file_lib.cc:87/:662 already pinned by filib/fctx
transcripts; re-driving it from this row invites cross-wire with the fctx P1 print ladder. Skip.

**R — the ref-count protocol ladder over REAL file_api.cc:28-:43 (~5 arms, new vectors for
symbols the donor link has run silently since 17q but the probes never walked linearly):**
- `R_ctor ref=1` — probe HEAP-allocates its own `ProbePolicy : FilePolicyBase` (local class, all 4
  virtuals overridden — do NOT reuse the donor StubFilePolicy here: its `fcache_release_stub_policy`
  teardown is entangled with the fcache/fflows replay vectors; fresh local class = zero cross-wire).
- `R_addref ref=2` — `add_ref()` (h:165).
- `R_del1 ref=1` — static `delete_file_policy(p)` (cc:39 read-back; policy still alive).
- `R_del0 gone=1` — second delete → `delete policy` (cc:40-:41); dtor assert(!ref) passes (cc:32).
  Print only the FLAG — no addresses, hygiene gate.
- `R_del_null silent=1` — `delete_file_policy(nullptr)` (cc:36 guard arm, nothing happens).
- Underflow posture assert(policy->ref_count) cc:38: do NOT probe it — hitting it ABORTS the probe
  process (`__assert_fail` live — no -DNDEBUG in donor GXX); record as
  panic-posture in PORT docs like the other pinned-UB arms (17s "flush over parked pop PANICS" precedent).

**U — UserFileDataBase dead-copy deviation observation arm (1 arm, optional):**
`U_ufd sz=8` is already the C line; the copy-path deviation has NO observable (bodies don't link
by definition). Recommend NOT probing (a probe that declares a copy would fail to LINK the probe
binary itself — that is the evidence; record grep evidence in PLAN/KNOWN DEVIATIONS instead).

**D — forwarder decl pins: none.** The four h:219-:224 decls are pinned in their body homes'
transcripts already (fflows file-position ladder; fconf G/M blocks). ZERO overlap arms here (§9 R8).

Vector hygiene: same donor gate `! grep -E '0x[0-9a-f]{6,}' vectors.txt` + printf-hygiene rules
(hoist mutating calls into locals before printf; the scratch probe already demonstrates the
pattern — e.g. read ref into a local via the FIXACC-visible member, printf after).
Probe link note for build.sh (measured this recon): linking ONLY stubs.o + file_api.o FAILS
(stubs.o drags FileFlows/FileService/FileIdentifier real symbols) — the probe links the WHOLE
donor obj set exactly like fconf does (:553-:556 recipe), so no new link fragility is introduced.

**Expected vectors.txt size: ~20 lines** (C/E/M + 11 P-arms + S + 5 R + DONE) — fconf's 20-line
oracle style; new file, committed, NEVER edited after landing.

## 8. PORT scoping — transcription plan + seam-close list (no code here)

1. **file_api.rs lands as canonical home.** Move (not copy): the 8 enum const-blocks from
   file_lib.rs:41-:88, UTF consts from file_lib.rs:32/:101, FileState struct file_lib.rs:90-:96,
   get_character_encoding file_lib.rs:99-:104, FileAction consts file_cache.rs:308-:310,
   FileCacheClearReport file_cache.rs:116-:121, FilePolicyApi trait file_cache.rs:545-:556,
   FilePolicyHandle file_cache.rs:558-:612. Every vacated site keeps a `pub use` re-export
   (17u file_config.rs precedent — dups resolved as re-exports, "all old bindings green").
   Add the NEW consts: FileProcessType trio, ENABLE_FILE_* trio, FILE_ALL_ON/OFF, UTF_16_LE_BOM
   byte pair. Add the NEW fns: the five inline position helpers (value-return form; C's
   `FilePosition*` in/out is a calling convention, the ladder arms pin observable in→out pairs).
2. **FilePolicyHandle stays the exact Rc<RefCell<PolicyStore>> model** — 17q pinned the
   ref ladder (1→2→1→0 set_file_policy pair, Rc::ptr_eq same-store) and KNOWN DEVIATIONS row 17q
   documents the alias model; consolidation must not "improve" the design while moving it.
   Rust posture for delete_file_policy(null): Option None at callers (17q doc: "the C null-argument
   arm = the port's Option-slot None"); Rust posture for the two asserts: debug_assert (existing) +
   pinned-panic narrative in deviations if the doc needs it.
3. **Do NOT land:** bitset wrapper type (word array stands, fid/17u contract), UserFileDataBase
   copy semantics (dead bodies — §3/§6; keep trait shape), any second get_file_processed_size /
   get_file_position / rule-id shim (§9 R8 — four decls, four already-ported body homes),
   FileConfigView/FileConfigLite two-view consolidation (17u LEFT-OPEN at file_config.rs:225-:250
   stays open; swapping re-arms every pinned 17p/17r vector).
4. **Doc-comment cite refresh rule (17u R5):** rows 17p-17u doc comments cite file_api.h line
   numbers with drift (e.g. file_cache.rs:545 "file_api.h:20+", :558 ":160-:172" vs actual :144-
   :172; file_lib.rs:90 "file_api.h:60" vs actual :110; NEXT.md's own 17v sketch cites
   "h:41-:113" / "h:224-:227" which are off-by-one generations — actual enum span h:43-:108,
   shim decls h:221-:224). Ground-truth cites in THIS plan win at fe29cbe; PORT child refreshes
   numbers only in comments it already touches.

## 9. Risks flagged for HARNESS/PORT children

- **R1 dtor assert posture (LIVE in the harness):** ~FilePolicyBase asserts !ref_count
  (file_api.cc:32) and the donor GXX has NO -DNDEBUG (build.sh:341 `GXX="g++ -std=c++17 -O0 -w"`,
  `__assert_fail` in the .o residue proves it). A static/stack policy outliving its last
  delete_file_policy → SIGABRT at exit — donor stubs.cc:330-:332 comment already pins this hazard
  ("heap: a static object would hit ~FilePolicyBase's assert(!ref_count) at exit"). Probe policy
  MUST be heap + fully drained (R_del0 proves drain), and MUST NOT hit the cc:38 underflow assert —
  it aborts, cannot be observed as a vector (§7 R-block note).
- **R2 atomics vocabulary lie (again):** `std::atomic_uint` (h:171) is seq_cst; the Rust port
  uses a plain u32 (17p/17q deviation precedent: "mutex/atomics not reproduced"). Single-threaded
  probe ⇒ observationally identical; keep the deviation citation at the file_cache.rs:558-:565 doc
  block when the handle MOVES — do not silently drop the deviation doc into a new module.
- **R3 re-point breakage is the ONLY real PORT risk:** include_str! parity replays compile against
  these constants across 26 test files; moving homes without `pub use` shims breaks fcache/fctx/
  fflows/filib/fcap/fcshare/fconf fixtures en masse. The 17u recipe (canonical home + pub use +
  all old bindings green, suite count strictly increases) is the contract; cargo test >= 446.
- **R4 dead-body trap:** UserFileDataBase copy ctor/assign/copy() have NO definitions in the tree
  (measured grep `UserFileDataBase::` = 0). Writing Rust equivalents = fabricated behavior.
  Witness posture + KNOWN DEVIATIONS sentence citing the grep and the C link-error semantics.
- **R5 dead define/enum trap:** ENABLE_FILE_* / FILE_ALL_ON / FILE_ALL_OFF / FileProcessType have
  ZERO consumers src-wide (measured greps). Port as vocabulary consts pinned on the wire by the E/M
  vectors — do NOT connect them to FileService::file_type_id_enabled et al. (the REAL enable path
  is file_service.cc statics, an unported row; conflating the dead masks with the live atomics
  would be a semantic invention the vectors cannot catch).
- **R6 enum width:** C enums of this header are 4-byte ints — already transcript-pinned
  (filib A_SZ_BOOL line "SZ_VERDICT=4 SZ_DIR=4 SZ_CAPST=4 SZ_SIGST=4"). Interim Rust homes use
  u32; keep u32 through the move; never isize/i32. (FileProcessType trio joins as u32.)
- **R7 finalFilePosition UNKNOWN→END quirk (measured fin_unk pos=3):** the else-if at h:193 has
  no UNKNOWN guard. The future mime row (file_mime_process.cc:785/793/805 sequence INIT→...→FINAL
  with UNKNOWN starts) depends on this exact promotion. Pin-not-fix; the P_fin_unk vector nails it.
- **R8 decl-vs-body split:** h:219-:224 declares FOUR bodies that live in file_service.cc:256,
  file_flows.cc:61, file_config.cc:104-:127 — all already ported (file_flows.rs:137/:163,
  file_config.rs:167/:199). "The umbrella TU owns these symbols" reading is WRONG at link time;
  a duplicate Rust port would fork ladders that three transcripts pin. Decls earn doc comments
  with body-home cites, nothing else.
- **R9 two-view LEFT-OPEN carried:** do not let the consolidation touch FileConfigView ↔
  FileConfigLite duality (file_lib.rs:1301-:1309, file_config.rs:225-:250). Same ruling as 17u.
- **R10 env facts (don't rediscover):** no `-lcrypto` (link the .so.3 by absolute path —
  fconf build.sh:5 `$LIBCRYPTO`; a scratch probe that links stubs.o STANDALONE fails — pull the
  whole donor obj set, and note `probe_sizes` once failed with "Permission denied" because a link
  error left a non-exec artifact; always re-check exit codes). 2-CPU cgroup: serial builds.
- **R11 naming:** directory is `fcapi_harness` per this task; NEXT.md said `fapi_harness`. Use
  fcapi_harness in build.sh header + docs, note the reconciliation for the next NEXT.md touch.

## 10. Session ritual

Read-only on snort3-src; no commit in snort3-rust; scratch probes under
/opt/data/cache/scratch (this recon's probe + objlist at scratch/row17v/ — reusable as the
C pin check, recompile rather than edit); build via `bash build.sh` in the harness dir;
vectors.txt is the oracle — harness runs first (C truth), PORT transcribes against pinned
numerals only, never re-derives from memory. Gate md5 `4826fc2233044a2d5429413faf0ae1af` is the
unchanged-donor invariant; probe hygiene no-`0x` gate invariant; suite total only ever increases
from 446.
