# fpolicy_harness PLAN — row 17x: file_api/file_policy.{h,cc} (the FilePolicy TU: FileRule table + enable-flag pairs + the type/signature lookup ladder over the 17v FilePolicyApi/FilePolicyHandle seam; probe-vectors-only)

Donor: `tools/finspect_harness` (row 17w, freshest; PLAN 379 L, stubs.cc 873 L — NEXT.md:116
"new `tools/fpolicy_harness` from the **finspect** donor"). Ground truth:
`/opt/data/snort3-src` @ fe29cbe7403acc0dd428065a69d8f29cc311c18e (read-only). Rust:
`/opt/data/snort3-rust` @ 5bebf3b. All cites below at fe29cbe unless marked
"build.sh/stubs.cc/PLAN.md/NEXT.md/vectors.txt".

**Row measurements (this recon, grep/wc-verbatim):** `file_policy.h` 94 L + `file_policy.cc`
216 L = 310 (matches NEXT.md:100/:146 "94+216 = 310"). `grep -c TEST_CASE file_policy.cc` =
**0**; `grep -c UNIT_TEST` on both files = **0** (no `#ifdef UNIT_TEST` fragments at all —
no FIXLIBUT/FIXCAPUT-style surgery can fire). Upstream test dir
`src/file_api/test/` (CMakeLists.txt + file_stats_test.cc only) has ZERO FilePolicy hits
(grep-0) — no upstream test TU to care about. `grep -c file_policy
tools/finspect_harness/build.sh` = **0** (measured; the task premise "NOT cp'd in donors at
all" VERIFIED here and at NEXT.md:111 "ZERO `file_policy` hits ... grep this pass, exit 1").

**C-premise correction (measured, flag for the harness child):** there is NO `static
g_file_policy` single-slot store and NO free `get_file_policy` function in this TU.
`nm` of the scratch-compiled `file_policy.o` (recipe §2) shows ZERO file-scope data objects
(only `V` vtable/typeinfo/typeinfo-name for FilePolicy). The policy storage is the
NetworkPolicy *member* `FilePolicy* file_policy = nullptr` (main/policy.h:215), new'd in
`NetworkPolicy::NetworkPolicy` (`file_policy = new FilePolicy;` policy.cc:57) and released
via `FilePolicyBase::delete_file_policy(file_policy)` in `~NetworkPolicy` (policy.cc:64);
the accessor pair is `NetworkPolicy::get_base_file_policy` (policy.h:196, def policy.cc:74)
and `NetworkPolicy::get_file_policy` (policy.h:197, def policy.cc:76). The `get_file_policy`
names in consumers are: `FileFlows::get_file_policy(Flow*)` STATIC (file_flows.h:69,
file_flows.cc:157-:162 — rides `fd->get_file_policy()` file_flows.h:127, member set at
file_flows.cc:150 `fd->set_file_policy(get_network_policy()->get_base_file_policy())`) and
the concrete `NetworkPolicy::get_file_policy` consumers in main/modules.cc:2298/2350
(FilePolicyModule::set / end — the config ladder, NOT part of this row's link closure).

## 1. Verbatim symbol inventory (all cites fe29cbe)

### file_policy.h (94 L) — complete

Includes: `<map>` (:23), `<vector>` (:24), `"file_api/file_api.h"` (:26 — REAL since 17v, the
FilePolicyBase home). Forward decl `namespace snort { class FileInfo; }` (:30).

- `struct FileVerdictWhen` (:33–:37): `uint32_t type_id = 0` (:35), `std::string sha256` (:36).
- `struct FileVerdictUse` (:39–:45): `FileVerdict verdict = FILE_VERDICT_UNKNOWN` (:41),
  `bool type_enabled` (:42), `bool signature_enabled` (:43), `bool capture_enabled` (:44).
- `class FileRule` (:47–:55): public `FileVerdictWhen when` (:50) + `FileVerdictUse use`
  (:51); `FileRule()` (:53) + `void clear()` (:54) out-of-line.
- `class FilePolicy: public snort::FilePolicyBase` (:57–:92) — the row's class; base home
  file_api.h:144-:172 moved REAL in 17v:
  - `FilePolicy() = default` (:61), `~FilePolicy() override = default` (:62) — defaulted;
    the compiler emits them at USE sites, not in this TU (nm: no `T FilePolicy::~FilePolicy`
    in file_policy.o — §2 R4).
  - `void policy_check(snort::Flow*, snort::FileInfo*) override` (:64).
  - `FileVerdict type_lookup(snort::Packet*, snort::FileInfo*) override` (:67, comment
    "called after file type is known" :66).
  - `FileVerdict signature_lookup(snort::Packet*, snort::FileInfo*) override` (:70,
    comment :69).
  - `void add_file_id(FileRule&)` (:72); `set_file_type/set_file_signature/set_file_capture
    (bool)` (:73–:75); `get_file_type/get_file_signature/get_file_capture() const` (:76–:78);
    `void load()` (:79); `void set_verdict_delay(int64_t)` INLINE (:80, writes verdict_delay).
  - private (:82): `match_file_rule(Flow*, const FileInfo*)` (:83), `match_file_signature(
    Flow*, const FileInfo*)` (:84), `std::vector<FileRule> file_rules` (:85),
    `std::map<std::string, FileVerdict> file_shas` (:86), `FileRule default_rule` (:87),
    `bool type_enabled = false` (:88), `bool signature_enabled = false` (:89),
    `bool capture_enabled = false` (:90), `int64_t verdict_delay = 0` (:91).
  - Exactly ONE `private:` in the header (:82) — FIXACC `assert n >= 1`-safe (§2).
  - NOT overridden: `log_file_action` (FilePolicyBase virtual, proven by StubFilePolicy
    overriding it at stubs.cc:369-:370) — FilePolicy inherits the base body (file_api.cc,
    REAL TU since 17v; fcapi PLAN:187 pin lists the 4-virtual protocol homes).

### file_policy.cc (216 L) — complete (0 UNIT_TEST fragments; two cppcheck-suppress
comment lines cc:69/:75 ride VERBATIM)

Includes: `file_policy.h` (:25), `file_api/file_capture.h` (:27 — REAL 17s, cp'd build.sh:63
+ FIXACC :261), `file_api/file_lib.h` (:28 — REAL, cp'd :63), `file_api/file_service.h`
(:29 — cp'd :63, header-only witness TU), `hash/hashes.h` (:30 — cp'd :65, hashes.cc REAL
compiled :396: provides `SHA256_HASH_SIZE 32` hashes.h:28). `using namespace snort;` (:32).

- `FileRule::clear()` cc:34–:42 — zeroes when.type_id/sha256 + the three use flags + verdict.
- `FileRule::FileRule()` cc:44–:47 — calls `FileRule::clear()`.
- `FilePolicy::set_file_type` cc:49–:52 / `set_file_signature` cc:54–:57 /
  `set_file_capture` cc:59–:62 — plain flag writers (h:88-:90 members).
- `FilePolicy::get_file_type` cc:64–:67 / `get_file_signature` cc:70–:73 (cppcheck-suppress
  :69) / `get_file_capture` cc:76–:79 (cppcheck-suppress :75) — the flag readers; the getters
  DO NOT read FileService (next.md:120 "read+arm the REAL FileService enable static trio" =
  the add_file_id/load arms arm the statics, the getters stay member-only — pin per cc).
- `FilePolicy::add_file_id(FileRule&)` cc:81–:111 — `file_rules.emplace_back(rule)` (:83);
  hex→bytes loop (:85–:100): per 2-char `std::stoi(hex.substr(offset,2),nullptr,16)` (:94) →
  `bytes.push_back` (:95) → `file_shas[bytes] = rule.use.verdict` (:99); then the ENABLE
  side-effects: `FileService::enable_file_type()` UNCONDITIONAL + `type_enabled = true`
  (:103–:104 production quirk), conditional `FileService::enable_file_signature()` (:106–
  :107) and `FileService::enable_file_capture()` (:109–:110) on the rule's use flags.
- `FilePolicy::load()` cc:113–:130 — `if (type_enabled or signature_enabled)` →
  `type_enabled = true; FileService::enable_file_type()` (:115–:119);
  `if (signature_enabled) FileService::enable_file_signature()` (:121–:122);
  `if (capture_enabled) FileService::enable_file_capture()` (:124–:125); then stamps the
  three flags into `default_rule.use` (:127–:129).
- `FilePolicy::match_file_rule(Flow*, const FileInfo*)` cc:132–:145 — first rule with empty
  sha256 and (`when.type_id == 0` OR `== file->get_file_type()`) (:139–:141); else
  `default_rule` (:144).
- `FilePolicy::match_file_signature(Flow*, const FileInfo*)` cc:147–:168 —
  `file->get_file_sig_sha256()` (:150) → `std::string sha(ptr, SHA256_HASH_SIZE)` (:152) →
  `file_shas.find` (:154); HIT + `verdict_delay > 0` → `verdict_delay--; return
  FILE_VERDICT_PENDING` (:157–:160, the delay counter decrements PER CALL); else hit verdict
  (:163); miss → `FILE_VERDICT_UNKNOWN` (:167).
- `FilePolicy::policy_check(Flow*, FileInfo*)` cc:170–:177 — TODO comment (:172);
  `file->config_file_type(type_enabled)` / `config_file_signature` / `config_file_capture`
  (:173–:175); `file->set_policy_id(0)` (:176 — the single-policy quirk, id 0).
- `FilePolicy::type_lookup(Packet*, FileInfo*)` cc:179–:185 — rule = match_file_rule (:181);
  re-arms signature/capture on the FileInfo (:182–:183); returns `rule.use.verdict` (:184).
- `FilePolicy::signature_lookup(Packet*, FileInfo*)` cc:187–:216 — if
  `rule.use.capture_enabled` (:191): `file->reserve_file(captured)` == FILE_CAPTURE_SUCCESS
  (:195) → `captured->store_file_async()` (:197) → `file->set_extracted_name` (:198) →
  empty-name arm `set_extracted_size(0) + delete captured` (:199–:203) else
  `set_extracted_cutoff(false)` (:204–:205); reserve-fail arm `delete captured` (:207–:208);
  `state.sig_state == FILE_SIG_DEPTH_FAIL → FILE_VERDICT_LOG` (:210–:212); fall-through
  `match_file_signature` (:215). The capture leg rides the REAL file_lib.o FileInfo bodies
  (file_lib.h:102 reserve_file, :107-:109 set_extracted_*) + REAL file_capture.o
  `store_file_async` (file_capture.h:90) — the 17s closure already compiled both.

## 2. Donor-closure diff vs tools/finspect_harness + witness table (retire vs NEW, stubs.cc cites)

**cp delta: TWO files (h + cc).** `file_policy.{h,cc}` have ZERO presence in the donor: not
in the cp braced list (build.sh:63 — enumerated, no file_policy entry; measured grep -c = 0),
not in the generic compile loop (build.sh:396 `for f in file_api file_config ... file_inspect;
do` — NEXT.md:111 pins the same). Delta = append `file_policy.h,file_policy.cc` to the :63
braces + append `file_policy` to the :396 loop (plain VERBATIM compile, no dir special-case).
Every OTHER include of the row TU is already resident/REAL: file_api/file_api.h (h:26; cp'd
:63, REAL TU since 17v compiled :396, FIXACC :261) + file_api/file_capture.h (cc:27; cp'd +
FIXACC :261, REAL since 17s) + file_api/file_lib.h (cc:28; REAL TU) + file_api/file_service.h
(cc:29; header-only, witness bodies live) + hash/hashes.h (cc:30; cp'd :65, REAL compiled
:396). Gates/grafts/shims/catch block: donor VERBATIM (retire rule). ZERO grafts fire on the
row TU (0 UNIT_TEST, 0 TEST_CASE — the fixacc/fixlIBUT/fixcapUT surgeries never see it; it
compiles byte-VERBATIM exactly like 17v file_api.cc / 17u file_config.cc / 17w file_inspect.cc
— the self-check pin pattern, finspect build.sh:618-:620 style, repeats here).
FIXACC optional: `file_policy.h` has exactly ONE `private:` (:82) so
`assert n >= 1` (build.sh:261-:266) passes IF the harness child adds
`"/file_api/file_policy.h"` to the :261 tuple — needed only if the probe reads/arms the
private table members (`file_rules`, `file_shas`, `verdict_delay`, `default_rule`) directly;
the cc:34-:216 public surface covers most arms. Pin the choice at build.

**Scratch-compile probe (REAL, this recon, /opt/data/cache/scratch/row17x):** copied the
finspect `copy/` tree VERBATIM, appended file_policy.{h,cc} from ground truth, compiled:
`g++ -std=c++17 -O0 -w -I$S/copy -I$NODE_INC -fsyntax-only` → SYNTAX_OK; real `-c` →
COMPILE_OK (zero grafts, zero sed on the row TU — the header closure holds as-is).
`nm -u --demangle file_policy.o | grep ' U ' | sort -u` → **59 U entries**:
**14 app + 45 libstdc++/libgcc plumbing** (string ops ×24, `_Rb_tree_*` ×3 — the `file_shas`
map — `__throw_*` ×6, `_Unwind_Resume`/`__cxa_{begin_catch,end_catch,rethrow}`,
`operator new`/`delete(void*,unsigned long)`, `strlen`, `__isoc23_strtol` ← cc:94 std::stoi,
`__errno_location`, `__cxa_atexit`/`__dso_handle` ← the cc:85-:100 local temporaries,
`_GLOBAL_OFFSET_TABLE_`, `__gxx_personality_v0`, `vtable for __cxxabiv1::__si_class_type_info`).

**Closure classification (measured per-symbol against donor `.o`s + `stubs.o`):**

| app U entry | closed by | cite |
|---|---|---|
| `snort::FileInfo::{config_file_type, config_file_signature, config_file_capture, get_file_type, get_file_sig_sha256, reserve_file, set_policy_id}` (7) | REAL `copy/file_api/file_lib.o` | verified `nm --defined-only` hits; FileInfo bodies are the 17r REAL TU |
| `snort::FileCapture::~FileCapture()` + `store_file_async[abi:cxx11]()` (2) | REAL `copy/file_api/file_capture.o` (plain) / `file_capture_probe.o` (3 defs incl D0/D1 verified for the probe variant) | 17s carry; probe link drops the plain .o (finspect build.sh:640-:642 pobjs rule), gate link keeps the `_ut` variant per :588-:594 |
| `snort::FilePolicyBase::~FilePolicyBase()` (D2) + `typeinfo for snort::FilePolicyBase` (2) | REAL `copy/file_api/file_api.o` | 17v REAL TU (the ref-protocol home); the h:57 base + h:62 defaulted dtor need the base dtor + typeinfo — both `T`/`V` in file_api.o (fcapi PLAN:187 pin: dtor x3 T, delete_file_policy T) |
| `snort::FileService::{enable_file_type, enable_file_signature, enable_file_capture}` (3) | **resident witnesses** `stubs.cc:596-:598` | NEXT.md:111 ":596-:598"; bodies in §retire table below |

`comm`-diff of the MANGLED U set vs `nm --defined-only` over the full donor member set +
`stubs.o` (exact 17w recipe, finspect PLAN:195-:198): **residue = 45 entries = exactly the
plumbing set, ZERO app residue.** The row closes against ALREADY-LINKED code: 9 entries
against REAL .o's + 3 against resident stubs.cc witnesses. **NEW witness bodies required:
ZERO** (measured — "witness delta expected ~ZERO" at NEXT.md:118 confirmed = exactly zero).

**New-witness table:** (empty by measurement).

**Witness RETIREMENT table (dup-symbol rule R5):**

| donor witness body | stubs.cc cite | disposition |
|---|---|---|
| `StubFilePolicy` class (4 virtuals w/ prints `POLICY type_lookup -> %d`, `POLICY signature_lookup -> %d`, `POLICY policy_check`, `POLICY log_file_action a=%d`) | stubs.cc:360-:370 (block comment :355-:359) | **KEEP — NOT retired.** Different class than `FilePolicy`: `nm -C stubs.o | grep -E 'FilePolicy|FileRule'` (this recon) shows ONLY `W StubFilePolicy::*` + `V` typeinfo/vtable for StubFilePolicy — ZERO T defs for `FilePolicy::*`/`FileRule::*`. The real file_policy.o's `T FilePolicy::*` (17 entries, nm-measured: ctor C1+C1/C2 of FileRule, clear, set/get ×3, add_file_id, load, match_*, policy_check, type_lookup, signature_lookup) + `V vtable/typeinfo/typeinfo-name for FilePolicy` collide with NOTHING in stubs.o. The dup-symbol landmine of 17r/17w (real .o re-defines a stubbed body, finspect PLAN:153) FIREs ZERO this row. |
| heap `static StubFilePolicy* g_stub_policy = new StubFilePolicy()` + `stub_file_policy()` + `fcache_release_stub_policy` (through REAL `FilePolicyBase::delete_file_policy`) | stubs.cc:374-:379 (heap-posture comment :374-:375 "a static object would hit ~FilePolicyBase's assert(!ref_count) at exit") | KEEP VERBATIM — the gate and the frozen replay twins ride it (fctx tests:229/:234, fflows tests:590/:801/:1091/:1149 print `POLICY base_file_policy -> stub`). |
| `fcache_set_policy_verdicts` / `fcache_stub_policy_refs` (probe arm + ref_count readout) | stubs.cc:381-:387 / :741-:744 (readout needs the FIXACC file_api.h entry, build.sh:261 + its NEW17q comment) | KEEP VERBATIM. |
| `NetworkPolicy::get_base_file_policy` witness → StubFilePolicy print | stubs.cc:696-:697 (block :665-:677, NEW17q) | KEEP VERBATIM — do NOT replace with a real FilePolicy hand-back: the NetworkPolicy object is PINNED raw storage, never constructed (stubs.cc:692-:693 `alignas … g_npolicy_storage`; the real ctor `new FilePolicy` policy.cc:57 is main/policy.cc monolith turf, unported). |
| `FileService::enable_*` trio | stubs.cc:596-:598 | KEEP, but see R2: the capture witness OMITS the real signature-cascade (file_service.cc:200-:204 `{ file_capture_enabled = true; enable_file_signature(); }` — REAL body, NOT cp'd: file_service.cc has grep-0 cp presence, NEXT.md:112 keeps file_service for a later row). Decide at build: replicate the cascade (byte-semantics vs real) or pin the omission as a documented deviation. |

**Gate delta: ZERO by construction.** Row adds 0 TEST_CASEs → the four-UT-TU gate (finspect
build.sh:587-:594) stays byte-ident: tail `All tests passed (114 assertions in 22 test cases)`
+ md5 `4826fc2233044a2d5429413faf0ae1af` (NEXT.md:118-:119: "gate must stay byte-ident
4826fc2233044a2d5429413faf0ae1af = sixth straight zero-regression row"; md5 re-verified this
recon on finspect gate.txt — finspect build.sh:629 asserts the same md5). Row self-check pins to repeat (finspect build.sh:618-:620
pattern): `grep -c TEST_CASE file_policy.cc = 0`, `grep -c UNIT_TEST` both files `= 0`.
Gate exposure today: `grep -c 'POLICY' finspect gate.txt` = 0 and `grep -c 'FilePolicy' ` = 0
(measured, 37 lines) — the gate only exercises StubFilePolicy through the cache seams'
handles, never any FilePolicy/FileRule body; adding file_policy.o to the gate link is
inert-by-construction (no gate TU calls it).

**nm pins to land in build.sh (17u/17v/17w style; scratch re-measured):**
(a) `nm -u --demangle copy/file_api/file_policy.o | grep ' U ' | sort -u > nm_policy.txt`;
`wc -l = 59`; (b) app-count grep `-cE 'U (snort::FileInfo::|snort::FileService::enable|
snort::FileCapture::|snort::FilePolicyBase::~FilePolicyBase|typeinfo for snort::
FilePolicyBase)' = 14`; (c) comm-diff vs the whole-member defined set leaves exactly 45,
`grep -c` app-pattern over the residue = 0; (d) dup-symbol verification (R5 inversion this
row): `nm -C copy/file_api/file_policy.o | grep -cE '^[0-9a-f]+ T (FilePolicy::(load|
policy_check|type_lookup|signature_lookup|add_file_id)|FileRule::clear)'` ≥ 6 and
`nm -C stubs.o | grep -cE 'T (FilePolicy::|FileRule::)'` = 0;
`nm copy/file_api/file_policy.o | grep -cE '_ZTV10FilePolicy$'` = 1 (V def, vtable pinned in
the row .o — Itanium ABI: first non-inline virtual keys here).

## 3. Rust landing/seam sites (grep FilePolicy|file_policy src/ tests/, measured)

### 3.1 Seams ALREADY landed (the row lands INTO them — do NOT fork)

| C item (cite) | Rust home (cite, grep-verified @5bebf3b) | verdict for 17x |
|---|---|---|
| `FilePolicyBase` 4 virtuals (file_api.h:151-:163) | `src/file_api/file_api.rs:229` `trait FilePolicyApi` (moved 17v; re-exported file_cache.rs:548) | KEEP as the trait the real FilePolicy IMPLEMENTS (NEXT.md:132-:133 "the real file_policy.rs implements FilePolicy on them — do NOT fork a parallel handle type"). |
| `FilePolicyBase*` ownership + ref protocol (h:148/:165/:168/:171; file_api.cc:28-:43) | file_api.rs:273 `struct FilePolicyHandle` (PolicyStore{Box<dyn FilePolicyApi>, ref_count u32}), ctor ref=1 :284-:291, `delete_file_policy` :301-:311 (mirrors cc:34-:43: `debug_assert!(st.ref_count > 0)` :310, decrements :311), `ref_count()` :313 | KEEP; the new side (FilePolicy-in-a-handle) rides `new_boxed` :288. |
| **policy-handle identity precedent (Rc::ptr_eq)** | file_api.rs:320-:321 `same_store` — "C pointer-identity compare `policy == stub_file_policy()` / `static_pol == pol` (file_flows probe B_CREATE / get_file_policy static): two handles front the same object iff they share the store" (doc :316-:319); family precedent file_cache.rs:61 "aliasing with Rc::ptr_eq instead of raw pointer ==" (file_lib.rs:2594/:2621, file_flows.rs:342/:741/:791) | The FilePolicy-vs-stub identity arms (probe will compare the real handle vs `stub_file_policy()` twins) ride `same_store` — the 17q-pin, no new identity machinery. |
| `FileFlows::get_file_policy(Flow*)` static + `fd->file_policy` member (file_flows.h:69/:120/:127; file_flows.cc:150/:157-:162) | file_flows.rs:289 `pub(crate) file_policy: Option<FilePolicyHandle>`; :456-:459 `~FileFlows` delete pair; file_flows.rs:1447 `get_file_policy_static` (fd && fd->file_policy rule); file_lib.rs:2466-:2470 `FileFlowsRef::file_policy_handle` (Handle → get_file_policy_static: fd && fd->file_policy)`; the null-deref panic arms file_lib.rs:2033/:2060/:2862/:2882/:2975/:2991 "C deref of null `FilePolicyBase*` … pinned-absent" | KEEP — the row only CHANGES which concrete impl sits behind the handle in new probe arms (StubFilePolicy twin vs real FilePolicy twin). |
| `NetworkPolicy::{get_file_policy, get_base_file_policy, add_file_policy_rule}` + ctor/dtor ownership (policy.h:195-:197/:215; policy.cc:57/:64/:75-:76/:79) | `trait NetworkPolicySeam::get_base_file_policy -> Option<FilePolicyHandle>` (file_lib.rs:1046-:1054, doc names the file_flows.cc:150 seam + "the C add_ref / delete_file_policy ref protocol observes the same object"); slot `FileEnvLite::network_policy: Option<Rc<RefCell<dyn NetworkPolicySeam>>>` (file_lib.rs:1121, default None :1163) | WITNESS-side stays: a Rust NetworkPolicy-twin in the fpolicy probe harness supplies the REAL FilePolicy handle through this seam (models policy.cc:57 new + :64 delete without porting main/policy.cc). |
| FileEnvLite policy slot audit (measured): NO dedicated FilePolicy slot exists — fields at file_lib.rs:1079-:1141 carry `network_policy` (:1121) and the FileService trio (FileServiceLite :932-:942, per-flag arms :953-:964 "the finspect stubs ride these") | — | If a new row probe needs a standing policy for the FilePolicy-in-a-handle arm, land it as `env.network_policy` seam armed with a `FilePolicyHandle::new_boxed(Box::new(FilePolicy::…))` — NO new FileEnvLite slot needed (the seam is the slot). |
| enable-flag trio statics (file_service.cc:189/:194/:200) | FileServiceLite statics + `set_file_type_enabled/set_file_signature_enabled/set_file_capture_enabled` (file_lib.rs:956-:964) | PORT-MEETS: the real FilePolicy `add_file_id`/`load` arms call exactly these (the Rust twins of cc:103-:110/:118-:125). If R2's capture cascade lands C-side, mirror it Rust-side (cc:110/:125 → set_file_capture_enabled + set_file_signature_enabled — actually the C cascade lives in FileService::enable_file_capture itself, so only if the Rust FileServiceLite::set_file_capture_enabled omits it — CHECK at port: pin one way and document). |
| FileRule/FileVerdictWhen/FileVerdictUse (h:33-:55) | ABSENT (grep `FileRule|FileVerdictWhen|FileVerdictUse` src/ = 0 hits except FileIdentifier::add_file_id docs, file_identifier.rs:202 — different `add_file_id`, the file-IDs trie) | NEW PORT `src/file_api/file_policy.rs`: plain structs riding the landed FileVerdict enums (file_api.rs); BTreeMap<Vec<u8> (or String from bytes), FileVerdict> for file_shas (C++ `std::map` = ordered — BTreeMap keeps `find` semantics exact); Vec<FileRule> for file_rules; `verdict_delay: i64` Cell-semantics; hex decode `u8::from_str_radix(&hex[o..o+2],16)` replicating cc:92-:97 (NOTE the C stoi would throw on junk — Rust `from_str_radix` → the panic-vs-skip deviation must be pinned; upstream config validation guarantees hex in production). CC:152 32-byte key: C++ takes the first 32 BYTES of the sha string — port slice(0..32) exactly. |
| FilePolicy methods (cc:34-:216) | ABSENT (grep confirms no FilePolicy struct in src/) | PORT ALL: FileRule::clear/ctor, set_/get_ flag pairs, add_file_id (with the FileServiceLite enable trio + the `type_enabled = true` quirk cc:104), load, match_file_rule/match_file_signature (private fns), policy_check/type_lookup/signature_lookup as the `FilePolicyApi` impl over the landed FileInfo setters; the signature_lookup capture leg rides the 17s `FileEnvLite::capture_factory` REAL factory (file_lib.rs:1128 decl, :1174 `RealFileCaptureFactory::new()` default) + `reserve_file`/`set_extracted_*` already ported — no witness needed there. |

### 3.2 Recommendation per symbol (port-vs-witness)

cc:34 FileRule::clear, :44 ctor, :49-:79 flag pairs, :81 add_file_id, :113 load, :132
match_file_rule, :147 match_file_signature, :170 policy_check, :179 type_lookup, :187
signature_lookup — **PORT ALL ten** (pure table/flag logic over landed seams; NEXT.md:132
"the real FilePolicy implementing the EXISTING 17v FilePolicyApi/FilePolicyHandle seam").
Config-module consumers (modules.cc:2221-:2352 FilePolicyModule — the `file_policy.rules`
ladder + `verdict_delay`/`enable_*` Value keys) — **WITNESS/out-of-scope** (main/ monolith,
never linked). The Rust twin harness arms go straight onto FilePolicy's public setters —
the ConfigLogger-style ladder of 17w is NOT this row's turf.

### 3.3 vectors plan (NEXT.md:119-:133 ladder, probe V-arms)

NEXT.md:120-:132 prescribes: FileRule::clear cc:34 + ctor :44; the set/get pairs cc:49-:79;
add_file_id cc:81-:112 (pinned against the NEXT.md mis-cite "FILE_ID_MAX word-array bitset —
17v word form &mut [u64; 1024/64]": that bitset is FileIdentifier::add_file_id,
file_identifier.rs:847-:870 — file_policy.cc has NO bitset; its add_file_id is the sha
table + enable trio. Harness child: vectors over the MEASURED body, not the NEXT.md paren-
thetical); load() cc:113-:131; match trio/policy_check/type_lookup cc:132-:186; the capture
ladder cc:187-:216 riding the 17s RealFileCaptureFactory closure; verdict_delay PENDING
arm cc:157-:160. Hygiene gate `! grep -E '0x[0-9a-f]{6,}'` carried verbatim (finspect
build.sh:646).

## 4. Frozen-oracle audit (tests/ POLICY witness lines, grep-counted this recon)

| test file | `grep -c POLICY` | policy witness lines (cites) | verdict |
|---|---|---|---|
| tests/fcache_parity_test.rs | 4 | :243/:247/:251 StubFilePolicy twins (`POLICY type_lookup -> {tv}`, `POLICY signature_lookup -> {sv}`, `POLICY log_file_action`) (comment :19) | ZERO EDIT — StubFilePolicy stays byte-VERBATIM C-side; twin untouched. |
| tests/fctx_parity_test.rs | 7 | :203/:207/:212/:216 StubFilePolicy twins; :229-:234 `POLICY base_file_policy -> stub` seam twin; :2007 comment | ZERO EDIT. |
| tests/fflows_parity_test.rs | 8 | :154/:158/:163/:167 twins; :590/:801/:1091/:1149 `hub.push("POLICY base_file_policy -> stub")` | ZERO EDIT — the file_flows handle chain never changes identity here. |
| tests/filib_parity_test.rs | 4 | :10/:189 `SZ_POLICY` (FilePolicyBase sizeof pin), :560/:569 `E4_KEEP_POLICY` (ref-protocol keep arm — 17r) | ZERO EDIT. |
| tests/fapi_parity_test.rs | 2 | :55 `PROBE_SIZEOF_FILE_POLICY_BASE = 16` (17v C_sz pin), :82 | ZERO EDIT — FilePolicy inherits FilePolicyBase (h:57): `sizeof(FilePolicy)` grows (vptr 8 + vector 24 + map 48 + FileRule 40-ish + 3 bools + i64) but NO existing oracle pins it; the fpolicy probe may add its OWN size line in the NEW vectors.txt. |
| tests/rules_parity_test.rs | 1 | :384 `POLICY now={} user={}` — policy_selector vocabulary, NOT FilePolicy | ZERO EDIT (irrelevant). |
| tests/numa_parity_test.rs | 22 | NUMA_POLICY_* enum names only | ZERO EDIT (irrelevant). |

**Verdict: ZERO test edits.** All frozen vectors/gate md5 pins ride unchanged (NEXT.md:86
"committed, NEVER edit"; gate md5 4826fc2233044a2d5429413faf0ae1af pinned in §2). The new
harness writes its OWN vectors.txt (frozen-vector twins of the NEW FilePolicy witness prints
are 17y-adjacent work, not a edit of existing files).

## 5. Risks (cites throughout)

- **R1 — no static slot / no dtor-of-global hazard (premise correction, §0/§pre):** the
  task-context guess "cc: static g_file_policy single-slot store, its dtor" is FALSE at
  fe29cbe. Nothing in file_policy.cc is file-scope; nothing is destroyed at exit. The real
  ownership is NetworkPolicy ctor/dtor (policy.cc:57/:64) — and in harness LAND,
  NetworkPolicy stays PINNED raw storage (stubs.cc:692-:693), so FilePolicy objects the
  probe news are probe-owned and must follow the heap-only rule (stubs.cc:374-:375 cites
  ~FilePolicyBase `assert(!ref_count)`, file_api.cc:31-:32 fcapi PLAN:156): pair
  ctor-ref=1 (file_api.cc:28-:29) with an explicit `delete_file_policy` before exit or the
  LIVE assert fires at teardown — same posture the fcapi PLAN:309-:310 probe-policy arm
  already pins ("do NOT reuse the donor StubFilePolicy here").
- **R2 — enable-flag default + witness-cascade drift:** defaults all-false
  (h:88-:90/:91) + load() OR-arm cc:115 + the add_file_id HARD-arms cc:103-:104
  (`FileService::enable_file_type(); type_enabled = true;` UNCONDITIONAL on every rule,
  signature/capture conditional cc:106-:110) are behavior-pinned vectors. But the C-side
  trio witness (stubs.cc:596-:598) omits the real cascade in `enable_file_capture`
  (file_service.cc:200-:204 calls `enable_file_signature()` too — REAL body unlinked,
  file_service.cc grep-0 in every build.sh cp-list; NEXT.md:112 defers the TU). First row
  where cc:109/:125 call-sites make the DRIFT observable. Pick one and pin: replicate the
  cascade in the stub body (instrumented, still witness — R5 safe since the real TU stays
  unlinked) and mirror in `FileServiceLite::set_file_capture_enabled`, or document as a
  frozen deviation. Silent inconsistency across C/Rust/frozen-vectors is the failure mode.
- **R3 — defaulted ctor/dtor do NOT emit in the row .o (nm-measured §2 note):** `~FilePolicy
  override = default` (h:52/:62 context :61-:62) has no `T` line in file_policy.o; the
  D1/D0 + C1/C2 emit at the FIRST use site (the probe TU). Probe link resolves base dtor
  through file_api.o (verified closed). No risk if the probe just news FilePolicy normally;
  do NOT `extern template`-style dodge.
- **R4 — vtable key-function placement:** the row .o DEFINES `V vtable/typeinfo for
  FilePolicy` (nm scratch §2(d)) because type_lookup/signature_lookup/policy_check are the
  first non-inline virtuals (Itanium key = first non-inline non-pure virtual, type_lookup
  decl order h:64 policy_check first — placement observed in the row .o, verified). Any
  future sed that inlines a virtual would move the vtable into the USE TU and create a
  missing-vtable link break; keep the VERBATIM compile (0 seds — §2).
- **R5 — dup-symbol inverse:** this row retires NONE (measured `nm -C stubs.o` FilePolicy/
  FileRule grep: all W/V under StubFilePolicy, zero T). The hazard to watch is the OPPOSITE
  of 17r/17w: if the harness child "helpfully" adds FilePolicy witness bodies for vector
  arms BEFORE the real .o lands (or keeps donor fcap/fctx-style FilePolicy stubs from older
  donors), the real file_policy.o T defs + V vtable collide. Landmine-pin assertion in
  build.sh §2(d).
- **R6 — FIXACC access creep:** add `"/file_api/file_policy.h"` to the build.sh:261 tuple
  ONLY (n=1 private, :82 — assert-safe); do NOT re-run the loop over untouched headers
  (assert `n >= 1` would fire on any zero-private header, 17w R8 trap, finspect PLAN
  header-note).
- **R7 — std::stoi/substr hex decode (cc:92-:97):** `__isoc23_strtol` + `__throw_
  invalid_argument`/`out_of_range` in the residue table prove the exception paths are LIVE
  in the .o; the Rust port's error posture on malformed hex must be pinned (panic == C
  throw; harness vectors never arm junk hex — config validation upstream, same posture as
  the frozen FileIdentifier arms filib vectors note file_lib.rs:847+).
- **R8 — probe-vs-gate capture-object split (17s carry):** `signature_lookup` cc:195-:208
  news/deletes FileCapture through the REAL file_lib.o + file_capture(_probe).o pair; in
  the probe link the plain `file_capture.o` is EXCLUDED (finspect build.sh:640-:642) — the
  new row must keep that pobjs filtering rule VERBATIM or the capture dtor arm doubles.

## 6. Session ritual (mirror fcapi/finspect PLAN §10)

1. cp donor → tools/fpolicy_harness (build.sh/catch/stubs/probe scaffold); rename pins
   (dir-name pin rule per NEXT.md row 17x — no reconciliation, NEXT.md:116-:119).
2. cp delta: two files into build.sh:63 + :396 (append, order-appended, no reflow);
   self-check grep block (TEST_CASE/UNIT_TEST × files = 0) appended after the 17w block.
3. nm pins §2(a)-(d) → artifact `nm_policy.txt` (gitignore carry, 17v PLAN:5 hygiene note).
4. Fresh probe.cc V-arms over the §3.3 ladder; gate untouched; expect tail
   114/22 + md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident = sixth straight zero-
   regression row (NEXT.md:118-:119). vectors hygiene gate verbatim (no 0x hex).
5. Rust child: `src/file_api/file_policy.rs` per §3.2 ports + trait impl on the 17v seam
   (file_api.rs:229/:273 — no fork, no new handle type); parity-test twins ride §4
   zero-edit ruling (new tests land in NEW files only).
