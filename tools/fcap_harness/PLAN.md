# fcap_harness PLAN — row 17s: file_capture.{h,cc} (the async-writer row)

RECON-measured against `/opt/data/snort3-src` @ fe29cbe7 (ground truth,
read-only) from snort3-rust @ b63e99a (row 17r landed: 415 tests / 49 suites /
0 FAILED, clippy 0). Every number below was measured this recon
(wc/grep/sed/nm-level reads of the fctx donor link), not estimated.
Harness donor = `tools/fctx_harness/` (NEWEST; its build.sh already compiles +
links `file_capture.cc` VERBATIM into the probe link — cp list line
`file_api/file_capture.h,file_capture.cc` + objs loop entry `file_capture`).

## 1. Scope definition + size (measured)

- `src/file_api/file_capture.h` = **150 lines**; `src/file_api/file_capture.cc` =
  **913 lines** (wc -l this recon). Compilable region = :1–:619 (everything
  after the main `#ifdef UNIT_TEST` at :620 is the gate's).
- Row scope: the full FileCapture class — buffer ladder (process_buffer /
  save_to_file_buffer / create_file_buffer), reserve/get/store, the
  stats surface (`collect_mem_usage`, `get_buffers_*`), and the async-writer
  half (`writer_thread` :79–118, `init` :166–172, `exit` :178–192,
  `flush` :194–209, `store_file_async` :564–584) — plus the Rust-side closure
  of the `Box<dyn FileCaptureApi>` seam (file_lib.rs:116–146, :218) over the
  already-live `file_mempool.rs` / `circular_buffer.rs` ports (landed early,
  17r).
- NOT in scope: `FileContext::process_file_capture` (file_lib.cc:1169–1187) —
  already ported 17r through the factory seam; 17s only swaps the
  `NoFileCaptureFactory` default (file_lib.rs:140–144) for a real impl.

## 2. TEST_CASE inventory (measured, with cites; grep for names, RUNNER for assertions)

Embedded UNIT_TEST block = **:620–:913** (`#ifdef` :620, block ends at the
final `#endif` :913 — same rfind+brace-guard excision site as the fctx
FIXLIBUT recipe). 4 TEST_CASEs, all tag `[file_capture]`:

| # | line | name | static CHECK/REQUIRE sites | fixture REQUIRE :782 | runtime assertions |
|---|---|---|---|---|---|
| A | :808 | Should not segfault when file mempool is not configured | 1 CHECK (:812) | — | 1 |
| B | :815 | Flush returns when no asynchronous captures are pending | 0 | — | 0 |
| C | :820 | Flush waits for the asynchronous writer to release its capture | 3 REQUIRE (:826,:831,:832) + 6 CHECK (:850,:851,:857,:859,:860,:861) = 9 | 1 | 10 |
| D | :864 | Flush keeps waiting between queued asynchronous captures | 5 REQUIRE (:872,:874,:881,:882,:883) + 6 CHECK (:901,:902,:907,:909,:910,:911) = 11 | 1 | 12 |

Static sites total **22**; expected runner total **23** (REQUIRE :782 inside
`AsyncCaptureFixture` ctor :779–:790 fires once per fixture = cases C+D).
Pin from the runner line ("… assertions in 4 test cases"), never from grep.
Order matters: cases run declaration order; B relies on A leaving
`file_storer == nullptr` (statics :60–:63 never touched before B's bare
`FileCapture::flush()` :817).

## 3. Include closure of file_capture.cc vs the fctx build.sh (diff = ZERO new TUs)

Includes at :27–:51 (+ file_capture.h's own :34–:39):

| include | fctx donor status |
|---|---|
| config.h | shim written by build.sh (`printf '#pragma once\n#define HAVE_ICONV 1\n'`) — already-verbatim |
| file_api.h (:39 via file_capture.h) | REAL TU, in objs loop (`file_api`) — already-verbatim |
| sys/stat.h, cassert, mutex/cv/queue/thread (:34–37 .h) | stdlib, free |
| log/messages.h (:37) | REAL header copied (`log/{messages.h,...}`); `ErrorMessage` body = witness stubs.cc:115 — already in link |
| main/thread.h (:38) | REAL header copied (`main/thread.h`); only reach = `get_instance_file` (used :577) — body is witness **stubs.cc:182** (`s = n; return s.c_str()`) — already in link |
| utils/stats/snapshot.h (:39) | REAL header-only (Builder::counter inline at snapshot.h:125/:131 — `collect_mem_usage` :586–:600 needs NO new TU) |
| utils/util.h (:40) | REAL TU pair in objs (`util`; `get_error` body util.cc:100; `SET_THREAD_NAME` is a macro → `pthread_setname_np`, util.h:45–46 → `-lpthread` already on the link line) |
| file_mempool.h (:42) | REAL TU in objs (`file_mempool`) — Rust port live (file_mempool.rs pub API matches) |
| file_stats.h (:43) | REAL TU in objs (`file_stats`); `file_counts` THREAD_LOCAL at file_stats.cc:45, `file_counts_update_buffers` body file_stats.cc:60 (used :858/:908) — already in link |
| UT-only: <atomic> <memory> <set>, catch/snort_catch.h (:45–:51) | catch.hpp vendored (`rules_harness` copy cp) + wrapper written by build.sh — already-verbatim |
| file_capture.h (:31) | REAL header copied; forward decls FileMemPool/FileInfo/stats resolve to real TUs (`file_mempool`, `file_lib`, header-only stats) |

**Classification: already-verbatim TUs 16/16, NEW TUs needed: 0, header-only
riders: snapshot.h/stats Builder.** `FileInfo` ctor/`set_file_size`/
`get_file_size`/`get_file_name` (used :413,:534,:829–830) live in the REAL
file_lib.o already linked; verify at harness time with an `nm -u` sweep on
`file_capture_ut.o` — expected witness delta ZERO.

## 4. `#ifdef UNIT_TEST` fragment table (every site; probe keep/excise decisions)

| site | content | probe TU (compiled WITH -DUNIT_TEST) | gate TU (-DUNIT_TEST verbatim) |
|---|---|---|---|
| :45–:51 | UT includes <atomic>/<memory>/<set> + catch | **KEEP** (scaffolding + catch.hpp need them) | keep |
| :65–:70 | 4 static hook fn-ptrs (`writer_test_hook`, `writer_idle_test_hook`, `flush_entry_test_hook`, `flush_predicate_test_hook`) | **KEEP** — the determinism contract; statics are FILE-LOCAL (set only by the UT scaffolding at :785–:788, never from probe.cc — so the probe MUST be the UT-compiled copy, see §5) | keep |
| :100–:103 + :112–:115 | writer_thread hook calls (post-pop / post-release) | **KEEP** | keep |
| :197–:200 + :203–:206 | flush entry hook + flush predicate hook | **KEEP** | keep |
| :620–:913 (main block) | UT namespace block | **KEEP :620–:807 ONLY** (FileCaptureTestAccess :623–:660 + AsyncWriterGate :663–:752 + static gate ptr :754 + hook wrappers :756–:774 + AsyncCaptureFixture :776–:806); **EXCISE the 4 TEST_CASEs :808–:912** — they belong to the gate binary (and REQUIRE outside a Catch session would abort) | KEEP everything verbatim (zero excision) |
| file_capture.h :46–:48 / :117–:119 | `friend struct FileCaptureTestAccess` fwd + friend decl | moot: FIXACC already flips the sole `private:` (:115 → public; measured count: 1 `private:`, 0 `protected:`) — friend is redundant, harmless either way | same |

Excision recipe (probe copy): `i = s.index("TEST_CASE (")` on the UT-compiled
copy, assert the tail holds exactly 4 `TEST_CASE (` + `#endif` rfind-guarded;
this is a DELTA vs the fctx FIXLIBUT recipe (which excises the LAST whole
block) — both live independently because file_capture.cc's early fragments are
hooks we WANT, unlike file_lib :37/:54.

## 5. What the 4 TEST_CASEs exercise + determinism contract (read, cited)

- **`FileCaptureTestAccess`** (:623–:660, friend of FileCapture): `resettable()`
  :625–:629 (mutex-held "no writer thread + empty queue" guard), `reset()`
  :631–:639 (delete mempool, zero block size, `file_storing=false`,
  `running=true`), `enqueue()` :641–:654 (push 1 or 2 captures + notify —
  bypasses `store_file_async` so NO sha256/name is set), `released_buffers()`
  :656–:659 (`file_mempool->released()`).
- **`AsyncWriterGate`** (:663–:752): 5-state rendezvous ladder —
  `writer_wait` (:666, blocks the writer INSIDE `writer_thread` :101–102 while
  it owns the popped capture), `writer_idle` (:674, counts post-`delete`
  transitions at :113–114, optional pause-first), `flush_entered` (:683,
  `std::set<std::thread::id> flush_callers` :686 ← hook :198–:199),
  `flush_predicate_evaluated` (:690 ← hook :204–:205 samples
  `files_waiting.empty()`/`file_storing` BEFORE the real predicate :207),
  waits/releases :698–:740, state :742–:752. Static gate ptr :754; hook
  wrappers :756–:774.
- **`AsyncCaptureFixture`** (:776–:806): REQUIRE resettable :781–:782, reset,
  installs all 4 hooks :784–:788, then **`FileCapture::init(1, 64)` :789 →
  REAL `new std::thread(writer_thread)` :171 — the gate itself IS
  multi-threaded (1 writer + 2 flush callers C :838/:843, +1 flush caller D
  :890; peak 3+main threads)**. Destructor releases writer + idle :794–:795
  BEFORE `FileCapture::exit()` :796 (join :188) — releasing after join would
  DEADLOCK the join.
- Case D adds the queue-drain subtlety: with 2 captures queued, after the
  writer deletes the first and its idle transition is PAUSED (:887), the flush
  predicate sees `!files_waiting.empty()` at :207 → flush keeps waiting;
  `wait_for_nonempty_idle_evaluation` :899 pins that the predicate WAS sampled
  in the nonempty/idle window (the :203–:206 hook).
- Because `reserve_file` copies a nameless FileInfo (:829, empty name),
  `store_file()`'s `fopen("", "wx")` :536 FAILS fast and returns :537–:540 →
  the gate writes NO files to disk (deviation worth pinning: disk path is
  exercised only as a no-op).
- **DETERMINISM VERDICT: the upstream suite is already hook-serialized — there
  is no racy window.** Harness rule for the fresh gate: run it as-is
  (`-DUNIT_TEST` verbatim TU, Catch session, N≥1 repeat); the 2-flushCaller
  order C :849 is resolved by `wait_for_flush_callers(2)` not by luck. For the
  PROBE vectors: drive the same ladder single-writer-thread where the hook
  ladder is armed; if a vector skips hooks (plain .o semantics), it MUST avoid
  flushing while `file_storing` can flip — prescribed: the probe arms the gate
  exactly like the fixture (minus REQUIRE) and releases in
  destructor order :794–:796. NEVER call `exit()` with a gate hook parked.
  THREAD_LOCAL note: `file_counts` (file_stats.h:85) is PER-THREAD — the
  `delete file` at :106 bumps the WRITER's counts; the :858/:908
  `file_counts_update_buffers()` + :859/:909 reads happen on the TEST thread,
  where `file_buffers_in_use` is recomputed from the SHARED mempool
  (file_stats.cc:60) — pin this cross-thread stats split in vectors (§8-2).

## 6. Gate plan + witness inventory for the probe link

- Gate binary (fcap link) = 4 UT TUs in one link (skill dup-symbol rule):
  **NEW [file_capture] (4 cases, §2)** + carry the 17r trio verbatim from fctx:
  [file_flows] 8/22, [file_mempool] 3/27, [file_cache] 7/42 (fctx gate.txt
  tail). Exclude the plain `file_capture.o` (and the trio's plain .o) from the
  gate objs.
- Probe link: identical fctx donor; probe TU list swaps `file_capture.cc`
  plain-compile → `-DUNIT_TEST` compile with the §4 TEST_CASE excision
  (scaffolding kept). Probe may still call FIXACC-public
  `init_mempool`/`capture_block_size` (stubs.cc:466–:479 pattern) for
  hookless buffer-ladder vectors, and the fixture-pattern ladder for
  async vectors.
- **Witness delta expected ZERO** (§3/§5): ErrorMessage stubs.cc:115,
  get_instance_file stubs.cc:182, file_counts + file_counts_update_buffers +
  get_error + pthread all REAL/-lpthread already. Confirm with
  `nm -u "$C"/file_api/file_capture_ut.o` sorted-comm.diff against the plain
  `file_capture.o` undefined list before writing stubs.
- Disk hygiene: store_file_async vectors (sha256 name via
  `FileInfo::sha_to_string` + `get_instance_file` witness ⇒ bare filename in
  CWD) — run probe from a fresh relative capture workspace (skill rule) or
  skip async-store-to-disk vectors; the 4 gate cases write nothing (§5).

## 7. Grafts (FIXACC + precedents)

- `file_capture.h` is **already in the fctx FIXACC list** (build.sh python
  `FIXACC` loop, file_list carries `/file_api/file_capture.h`) — verified this
  recon. Its single `private:` (:115, zero `protected:`) flips public; the
  `friend struct FileCaptureTestAccess` blocks (file_capture.h:46–:48/:117–:119)
  become redundant but stay untouched (verbatim header).
- No new defines/undefs: `UNIT_TEST` rides `-DUNIT_TEST` only on gate+probe
  UT compile; `THREAD_LOCAL` arm defs ride stubs.cc (fctx precedent).
- Everything else (policy/snort_config/daq/flowz/thread_config/trace grafts,
  shim headers, stubs.cc) = fctx donor VERBATIM (retire rule: donor untouched).

## 8. PORT scoping — the Rust model (no code in this row beyond scoping)

1. New `src/file_api/file_capture.rs` (mod.rs entry) — verbatim bodies: ctor
   :120–:129, dtor :131–:164 (the file_info-reserved vs transient split:
   `m_release` :145 vs `m_free` :151 + the two counts pairs),
   `init_mempool` :218–:234 (block = `block_len + size_of(FileCapture)` then
   8-align :228–:229 — Rust needs PINNED constants from a probe-printed C
   `sizeof(FileCapture)`/`sizeof(FileCaptureBlock)` vector, §9-3),
   `create_file_buffer` :236–:261 (mempool `m_alloc`/`allocated` — both LIVE:
   file_mempool.rs:181/:270), `save_to_file_buffer` :268–:344 (the
   `sizeof(*lastBlock)` payload-offset dance :294/:318/:335),
   `process_buffer` :361–:396, `reserve_file` :399–:458,
   `get_file_data` :471–:486, `write_file_data` :495–:526 (3-retry fwrite +
   ferror/EINTR/EAGAIN arms → Rust: capped retry loop over a slice write,
   ErrorMessage seam; errno-armed failure arms via env seam like the fctx
   armable witnesses), `store_file` :529–:561, `collect_mem_usage` :586–:600,
   `get_buffers_max`/`_in_use` :602–:614, `error_capture` :72–:76
   (already mirrored at file_lib.rs:174).
2. **Async model: single-thread, ORDER-faithful (17r precedent:
   `user_file_data_mutex` single-thread deviation, fctx PLAN §6-9).** Do NOT
   port `std::thread`/cv/mutex as live concurrency. Model: `files_waiting:
   VecDeque<Box<FileCapture>>` + `file_storing: bool` + a public
   `writer_step()` whose body is `writer_thread` :83–:117's ONE iteration
   verbatim (pop front → `file_storing=true` → `store_file` → `drop(file)`
   [the C `delete file` dtor :131–:164] → `file_storing=false` → the
   notify-all becomes "flush predicate re-evaluates"), plus `flush_until_idle`
   mirroring the predicate :207, and `resettable`/`reset` semantics of
   FileCaptureTestAccess as test-visible methods. Threads' interleavings are
   pinned ONLY as the orderings the C gate's vectors captured (§5 ladder:
   pop-before-store, store-before-release, nonempty-idle predicate evaluation
   before drain). Record as deviation: "no OS threads in Rust; the gate's
   hook ladder fixes the interleaving the vectors pin".
3. **Seam closure**: `impl FileCaptureApi for FileCapture` (reserve_file /
   get_file_capture_size / get_max_file_capture_size / set_data /
   process_buffer — trait file_lib.rs:116–:130) +
   `impl FileCaptureFactory for RealFileCaptureFactory` replacing
   `NoFileCaptureFactory`'s reach (file_lib.rs:136–:146); FileContext's
   `file_capture: Option<Box<dyn FileCaptureApi>>` (file_lib.rs:218) stays
   the trait object — no file_lib.rs struct surgery. The fctx N-block +
   fcache/fctx test captures (`HubCapture` tests/fctx_parity_test.rs:447/:528,
   `Cap` tests/fcache_parity_test.rs:445) stay as witnesses where vectors
   armed stub behavior; parity test gains `up_gate_capture_*` translations of
   the 4 [file_capture] cases against the single-thread model (case C/D
   become scripted `writer_step()` orders).
4. file_mempool.rs + circular_buffer.rs already live (17r) — the release
   queue behind `m_release`/`released()` (:656–:659 witness of case C/D) is
   modelled through them; no changes unless a vector exposes a gap.

## 9. Risks flagged for HARNESS/PORT children

1. **Thread lifecycle is the hang face.** `init()` spawns :171; `exit()` joins
   :188 — a parked gate hook (`writer_test_hook`/`writer_idle_test_hook`)
   joined-before-released DEADLOCKS (fixture dtor order :794–:796 is load
   bearing). Any probe/gate tweak must preserve release→exit order; add a
   timeout wrapper on the gate binary in CI terms (run twice, §ritual).
2. **THREAD_LOCAL `file_counts` vs shared mempool split** (§5): counts printed
   from the wrong thread WILL disagree — pin which counts land in which
   thread's `file_counts` before the port mirrors them into Rust's single
   FileCounts (file_stats.rs:106); vector labels must carry the thread id
   (`main`/`writer`).
3. **Layout constants**: the mempool slot is sized by `sizeof(FileCapture)`
   (:220) while the block header/ payload offsets are `sizeof(FileCaptureBlock)`
   (:121/:294/:481) — different, platform-pinned numbers. Rust models the
   payload as a `Vec<u8>` per slot; the ONLY truths are the probe-printed C
   sizes + the block-capacity math (:226–:231, :591–:593); pin them x2, never
   compute mentally.
4. Gate-order coupling: case B's zero-pending assumption depends on A not
   having spawned a writer and on the fixture reset (:781–:782) — never enable
   Catch random-order/shuffle in the gate run.
5. `nm` link check: UT variant adds <set>/<memory>/catch references; if any
   Catch singleton symbol leaks into the PROBE copy (TEST_CASE excision
   incomplete), the probe (no catch_main) fails to link — assert 0
   `TEST_CASE (` survive in the probe copy (the §4 recipe guard does this).

## 10. Session ritual (mirror fctx PLAN §9)

gate+probe md5 stability x2 clean rebuilds (x3 pre-commit); `cargo test` ≥ 415
zero FAILED + clippy 0; NEXT.md row-17s grep-guard → status; KNOWN DEVIATIONS
append (gradients: single-thread async model, init-thread never spawned in
Rust, per-thread counts merge, block-layout constants); NEXT.md refresh row
17t + stats line; commit+push code then docs (wiki trio for 17r OWED per
commit b63e99a — rides the same landing).
