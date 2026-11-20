//! Literal port of `file_api/file_module.{h,cc}` (row 18a — 86 + 379 =
//! 465 L; the file-id Module TU: `FileIdModule` — the 17-param table,
//! the 30-peg/`file_counts` readback pair, the lazy-`fc` set() ladder,
//! the ALWAYS-true end() through the includer/parser seams, the
//! load_config STEAL home (the 17w-frozen witness trio's real body,
//! cc:263-:266), the `file_trace` THREAD_LOCAL DEFINITION (h:43 decl,
//! cc:52 def home), the stats pair, and the two Lua `Command` exports —
//! `dump_file_cache` / `dump_file_cache_detail`).
//!
//! Donor oracle: `tools/fmod_harness` (tools/flog_harness donor, row
//! 17z lineage, PLAN 2.1). The row TU compiles byte-VERBATIM (`grep -c
//! 'TEST_CASE\|ifdef UNIT_TEST'` = 0/0 measured on BOTH files — probe-
//! vectors-only; build.sh self-checks pin it). vectors.txt (61 L) is
//! the frozen transcript this module's arms transcriptionally mirror;
//! gate.txt stays byte-ident to the `4826fc22…e1af` 114/22 chain
//! (tenth straight: the row TU has 0 TEST_CASE, so the gate link rides
//! it inert-by-construction, R6).
//!
//! INVERTED LANDMINE ROW (PLAN R1/R2, the fsvc-17y pattern turned
//! around): the row .o DEFINES what four donor harnesses witnessed —
//! the C1/C2 ctors, `load_config` (T) and `file_trace` (B collapse).
//! The flog-donor 31-L trio (stubs.cc :419/:423-:445 md5 9165739e…,
//! byte-ident across finspect/fpolicy/fsvc/flog = the dup proof) is
//! RETIRED harness-side ONLY (per-link rule: the frozen harnesses keep
//! their trio); the probes now run REAL heap `new FileIdModule`
//! objects, so the Rust port lands the REAL type, and `load_config`
//! keeps exactly the 17w-documented shape: an owned `Option<Rc<
//! RefCell<FileConfigLite>>>` slot (the frozen `FileInspect::new`
//! seam type) and `dst = self.fc.take()` — cc:263-:266 `dst = fc;
//! fc = nullptr;` IS literally `Option::take` (zero file_inspect.rs
//! edits: `FileInspect::new`, file_inspect.rs:314-:319, already
//! takes the slot by `&mut Option` + `take()`).
//!
//! Steal observability (probe V4, PRINTS-FROZEN — the real body prints
//! NOTHING; the old `FIM load_config stole=` line was witness-only and
//! vectors grep-asserts ZERO here): the REAL steal through the REAL
//! `FileInspect::new` (file_inspect.cc:48-:51 `fm->load_config(config)`)
//! + post-call readbacks — a stolen slot answers `None`, a fresh module
//!   answers `None` BEFORE any set() and the pointer AFTER (lazy fc), a
//!   second load answers `None` again; caller-owns == the last-Rc drop
//!   semantics.
//!
//! What stays a SEAM (PLAN §3, grep-verified residue classes — the row
//! .o's 42 U-residues = 4 APP-NEW + 2 LuaJIT-REAL + 5 libc + 31
//! plumbing):
//! * `parser_append_rules_special` (decl parser.h:60; body parser.cc
//!   turf, cc:259 live call) -> [`RulesAppendSeam`] (W1 witness prints
//!   the (file, includer) pair — pins the `"include "` prefix from
//!   cc:249-:250 AND the EMPTY-string end() quirk, R5).
//! * `ModuleManager::get_includer` (module_manager.cc:52; the body
//!   drags the monolith, grep cc:45-:58 — header cp'd REAL, body
//!   witness, PLAN 3) -> [`ModuleManagerSeam`] (armable null: cc:258
//!   `inc` flows STRAIGHT into the parser call, nullptr legal).
//! * `DecodeConfig::set_decompress_buffer_size` (decl mime/
//!   file_mime_config.h:72, body in the mime monolith, cc:245 live
//!   call) -> [`DecompressBufferSeam`] (W3 witness `=4096`).
//! * `ControlConn::query_from_lua` (control.cc:41-:48 — the upstream
//!   body IS the observable: the non-SHELL compile arm is a constant
//!   nullptr) — driver-side before any command body runs; every
//!   LogRespond then routes through the `ctrlcon == null` arm of the
//!   control.h:99-:100 macro -> [`fm_log`] (the LOGMSG-prefixed
//!   witness arms, vectors:22+:26-:55).
//! * the LuaJIT pair `luaL_optint`/`luaL_optstring` (cc:295/:320) —
//!   NEVER hand-stubbed (R4; real `libluajit.a` T defs, first
//!   third-party link in the lineage). Rust face: the two command
//!   bodies take the ALREADY-QUERIED args (`Option<i64>` /
//!   `Option<&[u8]>`) and the `unwrap_or` defaults pin the C
//!   sentinel defaults exactly (100 / nullptr; deviation row 18a —
//!   no `lua_State*` type exists in the Rust tree, so the Command
//!   table's `func` slots land as presence-bools over documented
//!   seam-shaped bodies, never fn pointers).
//! * `snort::Module` base plumbing (ctor triple, `sum_stats`/
//!   `reset_stats` base arms, Usage enum, ProfileStats/file_perf_stats,
//!   the Trace/TraceOption types, ProfileStats/file_perf_stats): NO
//!   Rust Module fork (the 17z ruling — the REAL framework/module.o
//!   closes it harness-side; `enum Usage { GLOBAL, CONTEXT, INSPECT,
//!   DETECT }` module.h:216 answers V1 `usage=0` as a const pin;
//!   `get_profile`/the trace slot ride data-free liveness tokens).
//! * `get_base_file_policy` seam: file_module.{h,cc} reference it ZERO
//!   times (grep of both ground files) — 18a does NOT touch it
//!   (PLAN 3; the NetPol resident witness trio stays untouched).
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::file_cache::{ControlConsole, FileCache};
use super::file_config::{FILE_ID_HELP, FILE_ID_NAME};
use super::file_identifier::FileMeta;
use super::file_lib::{EVENT_FILE_DROPPED_OVER_LIMIT, FILE_ID_GID, FileConfigLite};
use super::file_stats::{
    file_counts_update_buffers, file_stats_clear, file_stats_collect, file_stats_sum,
    FileStatsEnv, FileStatsHooks,
};
use crate::framework::counts::{CountType, PegInfo};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::value::Value;
use crate::utils::stats::snapshot::{DynamicStatsPolicy, Snapshot};

// ==================================================================
// the row TU's data homes (cc:52/:53) + the two h:39-:42 macros.
// ==================================================================

/// h:44 `extern THREAD_LOCAL const snort::Trace* file_trace;` +
/// cc:52 `THREAD_LOCAL const Trace* file_trace = nullptr;` — THE
/// definition home (the retired flog stubs.cc:196 standover def is
/// gone; `fcache_set_file_trace`'s ARM survives pointing at the live
/// var, R3). The landed tree has no Trace type (the trace row stays
/// queued): the row-observable face is the slot's NON-NULLNESS ONLY
/// (V3 `armed=1 set_trace_nulled=0 rearm=1`), so the slot models as a
/// data-free token (deviation row 18a). The file_lib.rs FILE_DEBUG
/// consumers ride the landed `FileTraceSink` seam (file_cache.rs:403),
/// NOT this slot.
pub struct TraceToken;

std::thread_local! {
    pub static FILE_TRACE: Cell<Option<&'static TraceToken>> = const { Cell::new(None) };
}

// (doc note, attaching to NOTHING on purpose) h:39-:40 `#define
// FILE_DEBUG(module_name, module_id, log_level, p, ...) trace_logf(...)`
// — the macro reaches trace/trace_api.h; not a code site in this TU
// (zero FILE_DEBUG calls in file_module.cc), so nothing transcribes.
// h:42 `#define GET_CURRENT_PACKET snort::DetectionEngine::
// get_current_packet()` — likewise unused here (its cited Rust twins
// already exist at file_lib.rs:1697, file_cache.rs:417/:1181).

/// cc:53 `extern THREAD_LOCAL snort::ProfileStats file_perf_stats;` —
/// the DEFINITION home is file_lib.cc:71 (nm `B file_perf_stats`; NOT
/// this TU, cite-only). ProfileStats has no landed Rust type (the
/// profile layer stays unported; V1 `prof_nonnull=1` is a liveness
/// pin only), so the slot rides the same data-free token (deviation
/// row 18a).
pub struct ProfileStatsToken;
pub static FILE_PERF_STATS: ProfileStatsToken = ProfileStatsToken;

// ==================================================================
// cc:55-:109 `static const Parameter file_id_params[]` — 17 params +
// terminator. Range strings (the `"0:max53"` family) have NO slot in
// the landed Parameter struct (deferred with the option-parsing
// layer, parameter.rs:36-:40 — the pattern is pinned in THIS comment,
// deviation row 18a, same ruling as 17z's FL_PARAMS):
//   type_depth 0:max53 | signature_depth 0:max53 | block_timeout
//   0:max31 | lookup_timeout 0:max31 | capture_memcap 0:max53 |
//   capture_max_size 0:max53 | capture_min_size 0:max53 |
//   capture_block_size 8:max53 | max_files_cached 8:max53 |
//   max_files_per_flow 1:max53 | show_data_depth 0:max53 |
//   decompress_buffer_size 1024:max31 (all PT_INT); the four
//   PT_BOOLs (block_timeout_lookup/trace_type/trace_signature/
//   trace_stream) and rules_file (PT_STRING) carry nullptr ranges.
// Help strings (the cc:58-:106 second literals — "stop type ID at
// this point" ... "file decompression buffer size") likewise have no
// slot; pinned verbatim in this comment.
pub const FMOD_PARAMS: [Parameter; 18] = [
    Parameter { name: Some("type_depth"), ptype: PtType::PtInt, deflt: Some("1460") },           // cc:57
    Parameter { name: Some("signature_depth"), ptype: PtType::PtInt, deflt: Some("10485760") },   // cc:60
    Parameter { name: Some("block_timeout"), ptype: PtType::PtInt, deflt: Some("86400") },        // cc:63
    Parameter { name: Some("lookup_timeout"), ptype: PtType::PtInt, deflt: Some("2") },           // cc:66
    Parameter { name: Some("block_timeout_lookup"), ptype: PtType::PtBool, deflt: Some("false") },// cc:69
    Parameter { name: Some("capture_memcap"), ptype: PtType::PtInt, deflt: Some("100") },         // cc:72
    Parameter { name: Some("capture_max_size"), ptype: PtType::PtInt, deflt: Some("1048576") },   // cc:75
    Parameter { name: Some("capture_min_size"), ptype: PtType::PtInt, deflt: Some("0") },         // cc:78
    Parameter { name: Some("capture_block_size"), ptype: PtType::PtInt, deflt: Some("32768") },   // cc:81
    Parameter { name: Some("max_files_cached"), ptype: PtType::PtInt, deflt: Some("65536") },     // cc:84
    Parameter { name: Some("max_files_per_flow"), ptype: PtType::PtInt, deflt: Some("128") },     // cc:87
    Parameter { name: Some("show_data_depth"), ptype: PtType::PtInt, deflt: Some("100") },        // cc:90
    Parameter { name: Some("rules_file"), ptype: PtType::PtString, deflt: None },                 // cc:93
    Parameter { name: Some("trace_type"), ptype: PtType::PtBool, deflt: Some("false") },          // cc:96
    Parameter { name: Some("trace_signature"), ptype: PtType::PtBool, deflt: Some("false") },     // cc:99
    Parameter { name: Some("trace_stream"), ptype: PtType::PtBool, deflt: Some("false") },        // cc:102
    Parameter { name: Some("decompress_buffer_size"), ptype: PtType::PtInt, deflt: Some("100000") }, // cc:105
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                  // cc:108
];

// ==================================================================
// cc:111-:144 `static const PegInfo file_pegs[]` — 30 pegs + END.
// The names pair 1:1 with the landed FileCounts fields (file_stats.h
// / file_stats.rs:108-:144 — the counts slot this row re-exposes
// through get_counts' reinterpret-cast arm, cc:172).
// ==================================================================
pub const FMOD_PEGS: [PegInfo; 31] = [
    PegInfo { peg_type: CountType::Sum, name: "total_files", help: "number of files processed" },                                  // cc:113
    PegInfo { peg_type: CountType::Sum, name: "total_file_data", help: "number of file data bytes processed" },                    // cc:114
    PegInfo { peg_type: CountType::Sum, name: "cache_failures", help: "number of file cache add failures" },                        // cc:115
    PegInfo { peg_type: CountType::Sum, name: "files_not_processed", help: "number of files not processed due to per-flow limit" },// cc:116
    PegInfo { peg_type: CountType::Max, name: "max_concurrent_files", help: "maximum files processed concurrently on a flow" },     // cc:117
    PegInfo { peg_type: CountType::Max, name: "buffers_max", help: "maximum number of file buffers that can be allocated" },        // cc:118
    PegInfo { peg_type: CountType::Now, name: "buffers_in_use", help: "number of file buffers currently in use" },                  // cc:119
    PegInfo { peg_type: CountType::Sum, name: "files_buffered_total", help: "number of files that entered multi-packet buffering" },// cc:120
    PegInfo { peg_type: CountType::Sum, name: "files_released_total", help: "reserved files released back to pool (cross-thread)" },// cc:121
    PegInfo { peg_type: CountType::Sum, name: "files_freed_total", help: "unreserved files freed back to pool (same-thread)" },     // cc:122
    PegInfo { peg_type: CountType::Sum, name: "files_captured_total", help: "files successfully reserved for external use" },       // cc:123
    PegInfo { peg_type: CountType::Sum, name: "file_memcap_failures_total", help: "alloc failed - file mempool exhausted" },        // cc:124
    PegInfo { peg_type: CountType::Sum, name: "file_reserve_failures", help: "any file reserve failure" },                          // cc:125
    PegInfo { peg_type: CountType::Sum, name: "size_below_min", help: "files rejected below minimum capture size" },                // cc:126
    PegInfo { peg_type: CountType::Sum, name: "size_above_limit", help: "files rejected above the capture size limit" },            // cc:127
    PegInfo { peg_type: CountType::Sum, name: "single_packet_files", help: "files fitting in a single packet" },                    // cc:128
    PegInfo { peg_type: CountType::Max, name: "buffers_used_max", help: "peak simultaneous buffer usage" },                         // cc:129
    PegInfo { peg_type: CountType::Sum, name: "buffers_allocated", help: "total blocks allocated from file mempool" },              // cc:130
    PegInfo { peg_type: CountType::Sum, name: "buffers_freed_total", help: "total blocks freed to pool (same-thread)" },            // cc:131
    PegInfo { peg_type: CountType::Sum, name: "buffers_released_total", help: "total blocks released to pool (cross-thread)" },     // cc:132
    PegInfo { peg_type: CountType::Sum, name: "buffers_free_errors", help: "block free operation failures" },                       // cc:133
    PegInfo { peg_type: CountType::Sum, name: "buffers_release_errors", help: "block release operation failures" },                 // cc:134
    PegInfo { peg_type: CountType::Sum, name: "sig_depth_exceeded", help: "files bypassing inspection due to signature depth limit" }, // cc:135
    PegInfo { peg_type: CountType::Sum, name: "file_lookup_timeouts", help: "files where DM never responded within timeout" },      // cc:136
    PegInfo { peg_type: CountType::Sum, name: "file_cache_hits", help: "file cache lookups that found a known verdict" },           // cc:137
    PegInfo { peg_type: CountType::Sum, name: "file_cache_misses", help: "file cache lookups that did not find a verdict" },        // cc:138
    PegInfo { peg_type: CountType::Sum, name: "file_cache_total_entries", help: "total files ever inserted into the file cache" },  // cc:139
    PegInfo { peg_type: CountType::Sum, name: "file_cache_full", help: "file cache at the configured entry limit - no room for new entry" }, // cc:140
    PegInfo { peg_type: CountType::Sum, name: "file_cache_failures", help: "file cache add failed for reasons other than being full (e.g., duplicate key)" }, // cc:141
    PegInfo { peg_type: CountType::Max, name: "file_cache_max_entries", help: "peak number of entries ever in the file cache" },    // cc:142
    PegInfo { peg_type: CountType::End, name: "", help: "" }, // cc:143 `{ CountType::END, nullptr, nullptr }`
];

// ==================================================================
// cc:175-:179 `static const RuleMap file_id_rules[]` — one live row
// (EVENT_FILE_DROPPED_OVER_LIMIT = 1, file_flows.h:40; the msg pin
// "file not processed due to per flow limit") + the { 0, nullptr }
// terminator (V1 `rule0=1 msg0_null=0`). RuleMap (module.h:77-:81
// { unsigned sid; const char* msg; }) has no landed Rust home — the
// pair rides this const (deviation row 18a: module-layer type, same
// ruling as the Module base).
// ==================================================================
pub const FMOD_RULES: [(u32, &str); 2] = [
    (EVENT_FILE_DROPPED_OVER_LIMIT as u32, "file not processed due to per flow limit"), // cc:177
    (0, ""), // cc:178 `{ 0, nullptr }` — the terminator; "" stands in
              // for the nullptr msg (the C loop stops on sid == 0
              // before reading msg; deviation row 18a)
];

// ==================================================================
// `class FileIdModule : public snort::Module` (h:46-:84). The C base
// triple (name, help, params) lands as THIS type's consts (17z
// ruling: no Rust Module base forked — real framework/module.o closes
// the base harness-side; FILE_ID_NAME/FILE_ID_HELP ride the landed
// 17u canonical home, file_config.rs:91-:95 — consumed this row,
// NEXT.md: the two consts' own note said the file_module row
// consumes them). h:80-:82 privates: `FileMeta rule` (NEVER touched
// by any cc body — grep of file_module.cc: zero reads/writes after
// the h decl; kept as the literal member), `FileConfig* fc =
// nullptr` (the owned slot == Option<Box<FileConfigLite>>: cc:197
// `fc = new FileConfig` hands ownership to the module, cc:150-:151
// dtor deletes it UNLESS stolen — the leak-vs-ownership pin, R5, ==
// Rust drop of the live Rc; cc:265-:266 steal == Option::take),
// `std::string magic_file` (h:83 — the SSO 32-B sizeof pin V0
// `str=32` is a C-layout fact, probe-pinned, never size_of; Rust
// side a plain String). Usage pin: h:65-:66 `get_usage() -> GLOBAL`
// == Usage::GLOBAL == 0 (module.h:216 unscoped enumerator order
// GLOBAL,CONTEXT,INSPECT,DETECT; V1 `usage=0`, const pin).
// ==================================================================
pub struct FileIdModule {
    /// h:80 `FileMeta rule` — declared, never written by any body in
    /// the TU (literal member keep, never read; the V0 `mod_ge=1`
    /// pin counts its contribution to the C object size only).
    pub rule: FileMeta,
    /// h:81 `FileConfig* fc = nullptr` — the owned slot (see above).
    /// The landed slot shape: `Rc<RefCell<FileConfigLite>>` == the
    /// frozen 17w seam type `FileInspect::new` consumes (file_inspect.
    /// rs:314 `&mut Option<Rc<RefCell<FileConfigLite>>>`; a Box slot
    /// would force an edit to that frozen ctor — deviation row 18a:
    /// the C single-owner raw-pointer delete rides the landed 17w
    /// Rc-drop model, owner-count unchanged, steal == take either
    /// way).
    pub fc: Option<Rc<RefCell<FileConfigLite>>>,
    /// h:82 `std::string magic_file` — set() arms the "include "
    /// prefix (cc:249-:250); end() appends it VERBATIM, empty
    /// included (cc:259, the R5 quirk).
    pub magic_file: String,
    /// the C `extern THREAD_LOCAL ProfileStats file_perf_stats`
    /// target (cc:53 extern; def file_lib.cc:71). get_profile hands
    /// the static token (V1 `prof_nonnull=1` liveness pin).
    profile: &'static ProfileStatsToken,
}

impl Default for FileIdModule {
    fn default() -> Self {
        Self::new()
    }
}

impl FileIdModule {
    /// cc:146 `FileIdModule() : Module(FILE_ID_NAME, FILE_ID_HELP,
    /// file_id_params) { }` — an EMPTY ctor body: fc stays null
    /// (h:81), magic_file stays empty, NO FileConfig yet (the lazy
    /// new rides the first set(), cc:196-:197 — R5).
    pub fn new() -> FileIdModule {
        FileIdModule {
            rule: FileMeta::default(),
            fc: None,
            magic_file: String::new(),
            profile: &FILE_PERF_STATS,
        }
    }

    /// Module base readbacks (module.cc get_name/get_help/get_gid/
    /// has_dynamic_stats): the triple consts + h:72-:73 `get_gid() ->
    /// FILE_ID_GID` (file_flows.h:35 = 150) + h:68-:69
    /// `has_dynamic_stats() -> true` (V1 `gid=150 usage=0 dyn=1`).
    pub fn get_name(&self) -> &'static str {
        FILE_ID_NAME
    }
    pub fn get_help(&self) -> &'static str {
        FILE_ID_HELP
    }
    pub fn get_gid(&self) -> u32 {
        FILE_ID_GID
    }
    pub const C_USAGE_GLOBAL: u32 = 0; // h:65-:66 (module.h:216 order)
    pub fn get_usage(&self) -> u32 {
        Self::C_USAGE_GLOBAL
    }
    pub fn has_dynamic_stats(&self) -> bool {
        true
    }
    /// Module::get_parameters() — the cc:146-triple param table.
    pub fn get_parameters(&self) -> &'static [Parameter; 18] {
        &FMOD_PARAMS
    }

    /// cc:154-:155 `set_trace(const Trace* trace) const { file_trace
    /// = trace; }` — writes this TU's THREAD_LOCAL definition (the
    /// V3 arm: set_trace(nullptr) after an arm answers null). const
    /// in C because the target is a thread_local, not a member —
    /// Rust models the same with the Cell.
    pub fn set_trace(&self, trace: Option<&'static TraceToken>) {
        FILE_TRACE.with(|t| t.set(trace));
    }
    /// the current-slot readback the probe uses after each arm (V3's
    /// armed=1/after=0/rearm=1 face).
    pub fn file_trace_armed() -> bool {
        FILE_TRACE.with(|t| t.get().is_some())
    }

    /// cc:157-:161 `get_trace_options()` — the FUNCTION-LOCAL static
    /// `static const TraceOption filetrace_options(nullptr, 0,
    /// nullptr);` returning its address: name=nullptr, id=0,
    /// help=nullptr (V1 `tr_opt=1 tname_null=1`). TraceOption
    /// (trace.h:55-:63, 3 fields) has no landed Rust type (the trace
    /// row stays queued) — the null-triple lands as the field tuple
    /// behind an identity fn (deviation row 18a: the C static's
    /// one-instance identity has zero Rust observable; V1 pins the
    /// triple only).
    pub fn get_trace_options(&self) -> (Option<&'static str>, u32, Option<&'static str>) {
        (None, 0, None)
    }

    /// cc:163-:164 `get_profile() -> &file_perf_stats` — the extern
    /// static token (def home file_lib.cc:71; V1 `prof_nonnull=1`).
    pub fn get_profile(&self) -> &'static ProfileStatsToken {
        self.profile
    }

    /// cc:166-:167 `get_pegs() -> file_pegs` (V1 `pegs=30 peg0=
    /// total_files` — the probe counts until CountType::END).
    pub fn get_pegs(&self) -> &'static [PegInfo; 31] {
        &FMOD_PEGS
    }

    /// cc:169-:173 `get_counts() const { file_counts_update_buffers();
    /// return reinterpret_cast<PegCount*>(&file_counts); }` — the
    /// alias arm: the returned slice IS the env's counts cell read
    /// back field-by-field in C-declared order (the cast == the
    /// FileCounts layout, file_stats.rs:108-:144 — the V7 pre/post/
    /// reset arms ride the same cell, the 17z R2 alias pattern).
    /// The Rust face returns the counts slot borrowed from env after
    /// firing the update_buffers pair (hooks == the two landed
    /// FileStatsHooks buffers_max/buffers_in_use witnesses).
    pub fn get_counts<'a>(
        &self,
        env: &'a mut FileStatsEnv,
        hooks: &dyn FileStatsHooks,
    ) -> &'a [u64; 31] {
        file_counts_update_buffers(env, hooks);
        let c = &env.file_counts;
        // the reinterpret_cast over the all-PegCount struct, C-declared
        // order, first 31 slots (file_pegs pairs 1:1; the 32nd member
        // file_memcap_failures_reserve stays OUT of the pegs — internal
        // only, file_stats.rs:145 "internal only; not in file_pegs[]").
        let base = std::ptr::addr_of!(*c) as *const u64;
        // SAFETY: FileCounts (file_stats.h:38-:72) is all-PegCount
        // (u64) members with no padding — the very fact the landed
        // file_stats.rs:29-:33 header pins for the file_stats_sum
        // flat walk ("all-PegCount with NO padding") — and the
        // struct carries 31 members (the 30 peg-keyed + the
        // internal file_memcap_failures_reserve), so the 31-slot
        // view reads initialized memory only. The C
        // reinterpret_cast is the same alias over the first
        // member's address.
        unsafe { &*base.cast::<[u64; 31]>() }
    }

    /// cc:181-:184 `get_rules() -> file_id_rules`.
    pub fn get_rules(&self) -> &'static [(u32, &'static str); 2] {
        &FMOD_RULES
    }

    /// cc:186-:192 `sum_stats(bool dump_stats) { if (dump_stats)
    /// file_stats_sum(); Module::sum_stats(dump_stats);
    /// file_counts_update_buffers(); }` — the landed file_stats_sum/
    /// update_buffers twins ride straight in; Module::sum_stats has
    /// zero observable in the pinned transcript (the harness's real
    /// module.o body walks its OWN statics; the V7 arms pin ONLY the
    /// file_stats pair order — a no-op comment keeps the slot, R2
    /// cite: the real module.o plumbing answers it harness-side).
    pub fn sum_stats(&self, dump_stats: bool, env: &mut FileStatsEnv, hooks: &dyn FileStatsHooks) {
        if dump_stats {
            file_stats_sum(env); // cc:189
        }
        // Module::sum_stats(dump_stats); — base-class plumbing, no
        // landed Rust base (17z ruling); zero print/zero observable
        // in the frozen V7 arms.
        file_counts_update_buffers(env, hooks); // cc:191
    }

    /// cc:194-:254 the 17-arm set() ladder. FIRST-LINE QUIRK (R5):
    /// cc:196-:197 `if (!fc) fc = new FileConfig;` runs BEFORE any
    /// name test — every first param arms the lazy config (mid-
    /// ladder, NOT the ctor), INCLUDING the bogus name (the ladder
    /// falls through to the cc:252 return true with fc armed). Arms write
    /// FileConfigLite slots straight (the landed 17q struct).
    /// decompress_buffer_size leaves the FileConfig type entirely:
    /// cc:245 targets `FileService::decode_conf` (file_service.h:99,
    /// the D static; decode_conf STAYS a seam per 17y — no
    /// DecodeConfig in src/) via the seam. rules_file (cc:247-:251)
    /// builds magic_file = "include " + v.get_string(). The final
    /// `return true` is UNCONDITIONAL (bogus names answer TRUE — V2
    /// `ret=1111` incl. x=bogus). Inert C receivers (name, conf)
    /// drop from the Rust signature (17z precedent).
    pub fn set(&mut self, v: &Value, deco: &mut dyn DecompressBufferSeam) -> bool {
        if self.fc.is_none() {
            // cc:196-:197 lazy new FileConfig — FileConfigLite::
            // default() == the C `FileConfig()` member defaults, the
            // landed 17u canonical const table (DEFAULT_FILE_TYPE_
            // DEPTH 1460 ... file_config.rs:33-:70); h:36 stays
            // untouched.
            self.fc = Some(Rc::new(RefCell::new(FileConfigLite::default())));
        }
        // the RefCell borrow == the C raw-pointer deref window; the
        // slot's RefCell exists ONLY to ride the frozen FileInspect
        // seam type (deviation row 18a) — nothing here reborrows it
        // while this arm runs.
        let fc_slot = self.fc.as_ref().unwrap();
        let fc = &mut *fc_slot.borrow_mut();
        if v.is("type_depth") {
            fc.file_type_depth = v.get_int64(); // cc:199-:200
        } else if v.is("signature_depth") {
            fc.file_signature_depth = v.get_int64(); // cc:202-:203
        } else if v.is("block_timeout") {
            fc.file_block_timeout = v.get_int64(); // cc:205-:206
        } else if v.is("lookup_timeout") {
            fc.file_lookup_timeout = v.get_int64(); // cc:208-:209
        } else if v.is("block_timeout_lookup") {
            fc.block_timeout_lookup = v.get_bool(); // cc:211-:212
        } else if v.is("capture_memcap") {
            fc.capture_memcap = v.get_int64(); // cc:214-:215
        } else if v.is("capture_max_size") {
            fc.capture_max_size = v.get_int64(); // cc:217-:218
        } else if v.is("capture_min_size") {
            fc.capture_min_size = v.get_int64(); // cc:220-:221
        } else if v.is("capture_block_size") {
            fc.capture_block_size = v.get_int64(); // cc:223-:224
        } else if v.is("max_files_cached") {
            fc.max_files_cached = v.get_int64(); // cc:226-:227
        } else if v.is("max_files_per_flow") {
            fc.max_files_per_flow = v.get_uint64(); // cc:229-:230 (the
            // ONE u64 slot — file_config.h:66 asym kept by the 17u
            // canonical struct)
        } else if v.is("show_data_depth") {
            fc.show_data_depth = v.get_int64(); // cc:232-:233
        } else if v.is("trace_type") {
            fc.trace_type = v.get_bool(); // cc:235-:236
        } else if v.is("trace_signature") {
            fc.trace_signature = v.get_bool(); // cc:238-:239
        } else if v.is("trace_stream") {
            fc.trace_stream = v.get_bool(); // cc:241-:242
        } else if v.is("decompress_buffer_size") {
            // cc:244-:245 FileService::decode_conf.set_decompress_
            // buffer_size(v.get_uint32()) -- the W3 seam (mime row
            // turf; 17y decode_conf STAYS SEAM). Note get_UINT32,
            // not int64 (the only uint32 get in the ladder).
            deco.set_decompress_buffer_size(v.get_uint32());
        } else if v.is("rules_file") {
            // cc:247-:251 magic_file = "include " + v.get_string()
            self.magic_file = "include ".to_string();
            self.magic_file.push_str(&String::from_utf8_lossy(v.get_string()));
        }
        true // cc:253 (unconditional)
    }

    /// cc:256-:261 `end() { const char* inc =
    /// ModuleManager::get_includer(get_name());
    /// parser_append_rules_special(magic_file.c_str(), inc);
    /// return true; }` — ALWAYS true; appends EVEN WHEN EMPTY (V2:
    /// end-before-any-set -> parser_append_rules_special("",
    /// "MODULE-INC"), R5 pin); the includer flows straight in, the
    /// null arm legal (V2_end_nullic). get_name() == FILE_ID_NAME ==
    /// "file_inspect" (the W2 `mod=file_inspect` line).
    pub fn end(
        &self,
        mgr: &mut dyn ModuleManagerSeam,
        parser: &mut dyn RulesAppendSeam,
    ) -> bool {
        let inc = mgr.get_includer(self.get_name()); // cc:258
        parser.parser_append_rules_special(&self.magic_file, inc); // cc:259
        true // cc:260
    }

    /// cc:263-:266 load_config(FileConfig*& dst) — THE steal home the
    /// 17w trio witnessed: `dst = fc; fc = nullptr;` — literally
    /// `Option::take`. Prints NOTHING (the FIM line was witness-only;
    /// vectors grep-assert ZERO here). Plain member fn, NOT virtual
    /// (h:61). V4: post-steal readback answers None (V4_steal_a
    /// `post_null=1`); fresh-before-set answers None, fresh-after-one
    /// set hands the Rc, steal-again answers None (V4_steal_b
    /// `pre_null=1 post_got=1 again_null=1`). The caller takes the
    /// Rc == the C caller takes the raw pointer and owns it
    /// (`delete dst2` in the probe == Rust drop of the last Rc).
    /// Drop-glue: with a stolen slot, ~FileIdModule (cc:148-:152
    /// `if (fc) delete fc;`) SKIPS the delete exactly like the Rust
    /// drop of {None slot} — the same module's Rc, once stolen, is
    /// gone by construction.
    pub fn load_config(&mut self, dst: &mut Option<Rc<RefCell<FileConfigLite>>>) {
        *dst = self.fc.take(); // cc:265-:266
    }

    /// cc:269-:273 `collect_dynamic_stats(builder, policy)` — pure
    /// delegation to file_stats_collect (landed 17q twin; the V-none
    /// arms ride that row's frozen fstats vectors; builder half ==
    /// the landed Snapshot face, 16n/17y precedent).
    pub fn collect_dynamic_stats(
        &self,
        snapshot: &mut Snapshot,
        policy: &DynamicStatsPolicy,
        env: &FileStatsEnv,
        hooks: &dyn FileStatsHooks,
    ) {
        file_stats_collect(env, snapshot, policy, hooks); // cc:272
    }

    /// cc:275-:279 `reset_stats() { file_stats_clear();
    /// Module::reset_stats(); }` — the landed file_stats_clear twin;
    /// the Module:: arm is base plumbing, zero observable (same
    /// ruling as sum_stats).
    pub fn reset_stats(&self, env: &mut FileStatsEnv) {
        file_stats_clear(env); // cc:277
        // Module::reset_stats(); -- see sum_stats.
    }

    // dtor (cc:148-:152): `if (fc) delete fc;` — Rust: the live Rc
    // in `self.fc` drops with the struct; a stolen slot (None) drops
    // nothing. Zero body to transcribe; the probe pins it through
    // the leak-vs-ownership arms (V4, R5). No Rust Drop impl needed
    // -- field-ordered drop IS the translation.
}

// ==================================================================
// the four APP-NEW witnesses of the scratch nm-join (PLAN 0.3: 65 U
// entries, 23 resolved by the 17z donor closure, 42 survivors = 4
// APP-NEW + 2 LuaJIT-REAL + 5 libc + 31 plumbing) land as three
// traits + driver-side pre-reads. The LuaJIT pair stays REAL in the
// harness (libluajit.a T defs, R4) and has NO Rust counterpart: no
// lua_State type exists in the src/ tree (src/lua is the jsnorm row
// turf), so the command bodies take the ALREADY-QUERIED arg
// (deviation row 18a — the Command table's fn-pointer slots land as
// documented presence-bools over these seam-shaped bodies; the
// bodies' arms themselves transcribe verbatim).
// ==================================================================

/// W1 — global-scope `parser_append_rules_special(const char* file,
/// const char* includer)` (decl parser/parser.h:60; body parser.cc
/// turf — the header cp drags the 6-header detection chain, zero
/// TUs, PLAN 0.1; the mangled `_Z27parser_append_rules_specialPKcS0_`
/// matches). The witness prints the (file, includer) pair, pinning
/// cc:259 arg-passing verbatim incl. the set() "include " prefix and
/// the EMPTY-string end() quirk (R5; vectors:6/:9/:14).
pub trait RulesAppendSeam {
    fn parser_append_rules_special(&mut self, file: &str, includer: Option<&str>);
}

/// W2 — `snort::ModuleManager::get_includer(const char* module)`
/// (module_manager.cc:52; the body drags plugin_manager/lua_coreinit/
/// the monolith, grep cc:45-:58, so it stays a witness; header cp'd
/// REAL for the decl — analyzer_command.h:33 drags the DIOCTL graft,
/// PLAN 0.2b). Armable null: cc:258's `inc` flows STRAIGHT into W1
/// with a nullptr legal (vectors:8/:9 includer='(null)').
pub trait ModuleManagerSeam {
    fn get_includer(&mut self, module: &str) -> Option<&str>;
}

/// W3 — `snort::DecodeConfig::set_decompress_buffer_size(uint32_t)`
/// (decl mime/file_mime_config.h:72, reached through the stubs
/// file_service.h chain; the BODY lives in the mime monolith, NOT in
/// the closure; live call cc:245). 17y ruled decode_conf STAYS SEAM
/// (no DecodeConfig in src/, grep-0) — this set() arm rides the same
/// seam face.
pub trait DecompressBufferSeam {
    fn set_decompress_buffer_size(&mut self, v: u32);
}

// ------------------------------------------------------------------
// control.h:99-:100 `#define LogRespond(cn, ...) do { if (cn)
// cn->respond(__VA_ARGS__); else snort::LogMessage(__VA_ARGS__);
// } while(0)` — one adapter transcribes the macro's routing once:
// the ctrlcon half (the `ControlConn*` from query_from_lua) wins
// when non-null, else every line routes to the driver's LogMessage
// witness sink (the harness `LOGMSG <line>` prefix, vectors:22+).
// query_from_lua's UPSTREAM-VERBATIM non-SHELL body (control.cc:
// :41-:48, constant nullptr — the SHELL arm would drag Control-
// Mgmt) means the frozen probe ALWAYS takes the else arm (the
// every-LINE-LOGMSG grep evidence) — but the if-arm stays live for
// a driver that arms a real console (the fcache VecConsole twin).
// ------------------------------------------------------------------
pub struct MacroConsole<'a> {
    /// the `if (cn)` half — ControlConn::query_from_lua's answer
    pub cn: Option<&'a mut dyn ControlConsole>,
    /// the `else snort::LogMessage(...)` half (witness sink)
    pub sink: &'a mut dyn FnMut(&str),
}
impl ControlConsole for MacroConsole<'_> {
    fn respond(&mut self, msg: &str) {
        match &mut self.cn {
            Some(c) => c.respond(msg),
            None => (self.sink)(msg),
        }
    }
}

// ==================================================================
// cc:281-:307 `static int dump_file_cache(lua_State* L)`.
// Driver-side pre-reads stand in for the two C in-body queries:
// query_from_lua -> ctrlcon (Constant nullptr at fe29cbe non-SHELL,
// control.cc:41-:48 VERBATIM); FileService::get_file_cache() -> the
// Option handed here (the REAL D static at file_service.cc:54 armed
// through the donor seam); `luaL_optint(L, 1, 100)` ->
// max_entries.unwrap_or(100) (the cc:295 sentinel default; macro
// arms run through MacroConsole so the LogRespond null-branch
/// routing itself stays IN this TU's transcription).
// ==================================================================
pub fn dump_file_cache(
    out: &mut MacroConsole,
    cache: Option<&mut FileCache>,
    max_entries: Option<i32>,
) -> i32 {
    // cc:283-:284 the two queries; cc:286-:290 the cache-null arm
    // (LogRespond -> MacroConsole; V6 line "File cache not
    // available" LOGMSG-prefixed, vectors:22).
    let cache = match cache {
        Some(c) => c,
        None => {
            out.respond("File cache not available\n");
            return 0; // cc:289
        }
    };
    let max_entries = max_entries.unwrap_or(100); // cc:295 luaL_optint
    // cc:292-:294 comment kept verbatim: "-1 is the sentinel for
    // "dump every entry"; otherwise the count must be >= 1. Any
    // other value (0 prints nothing; negatives would wrap to a huge
    // unsigned count) is rejected."
    if max_entries < 1 && max_entries != -1 {
        // cc:296-:301 the reject arm (vectors:31 count-0, :32 -2) --
        // the %d prints the SIGNED value pre-cast.
        out.respond(&format!(
            "Invalid row count: {}. Use -1 for all entries, or a value >= 1\n",
            max_entries
        ));
        return 0; // cc:300
    }
    // cc:303-:304 `unsigned count = (max_entries == -1) ?
    // std::numeric_limits<unsigned>::max() : (unsigned)max_entries;`
    let count: u32 = if max_entries == -1 {
        u32::MAX
    } else {
        max_entries as u32
    };
    // cc:305 cache->dump_cache(ctrlcon, count) — the REAL file_cache.
    // cc:1031 body (landed file_cache.rs:2589; ITS internal Log-
    // Respond arms ride the same MacroConsole routing: the
    // "Total number of cache entries"/table-header/"... displayed
    // N of M" lines, vectors:27-:37/:39-:42).
    cache.dump_cache(out, count);
    0 // cc:306 `return 0;` — the Lua return-count; inert outside a
      // real lua_State, kept literal
}

// ==================================================================
// cc:309-:351 `static int dump_file_cache_detail(lua_State* L)`.
// `luaL_optstring(L, 1, nullptr)` -> sha: Option<&[u8]>; the cc:320
// default IS the nullptr (V1_cmds def1_null=1), so no default fold,
// just the arm.
// ==================================================================
pub fn dump_file_cache_detail(
    out: &mut MacroConsole,
    cache: Option<&mut FileCache>,
    sha: Option<&[u8]>,
) -> i32 {
    let cache = match cache {
        Some(c) => c,
        None => {
            out.respond("File cache not available\n"); // cc:316 (vectors:23)
            return 0;
        }
    };
    // cc:320-:325 `if ( !sha or !*sha )` — the nullptr default OR an
    // EMPTY string both answer the usage line (vectors:43 null-arg,
    // :44 empty-arg).
    let sha = match sha {
        Some(s) if !s.is_empty() => s,
        _ => {
            out.respond("Usage: file_inspect.dump_file_cache_detail(<sha256_prefix>)\n");
            return 0; // cc:324
        }
    };
    // cc:327-:329 comment verbatim: "A SHA256 is 32 bytes == 64 hex
    // characters, so a prefix must be 1..64 hex digits. Validate up
    // front to avoid walking the whole cache (under lock) for input
    // that can never match."
    // cc:330-:335 std::string sha_prefix(sha); length gate (vectors:
    // :45, the 65-a line).
    if sha.len() > 64 {
        out.respond("Invalid SHA256 prefix: length must be 1-64 hex characters\n");
        return 0;
    }
    // cc:337-:347 the per-char ladder: isxdigit (C-locale ASCII hex;
    // glibc-pinned through the real harness libstd, the "zz" reject
    // vectors:46) THEN toupper IN PLACE — the cc:345-:346 comment
    // pins the why ("Normalize to uppercase to match sha_to_hex()'s
    // uppercase output."): lowercase "ab" matches the 0xAB SHA row
    // (vectors:47-:54). A mid-run non-hex byte rejects before the
    // table call; the half-normalized prefix dies with the local
    // (C: returns before dump_cache_entry — same observable).
    let mut prefix: Vec<u8> = Vec::with_capacity(sha.len());
    for c in sha {
        if !c.is_ascii_hexdigit() {
            out.respond("Invalid SHA256 prefix: only hex characters (0-9, a-f, A-F) are allowed\n");
            return 0; // cc:341-:343
        }
        prefix.push(c.to_ascii_uppercase()); // cc:346
    }
    // cc:349 cache->dump_cache_entry(ctrlcon, sha_prefix) — the REAL
    // file_cache.cc:1073 body (landed file_cache.rs:2647): the match
    // arm prints SHA256/File Name/... (vectors:47-:54), the no-match
    // arm the cc:1111-cited reject line (vectors:55).
    cache.dump_cache_entry(out, &prefix);
    0 // cc:350
}

// ==================================================================
// cc:353-:359 `static const Parameter dump_file_cache_params[]` —
// V1_cmds `params0=max_entries def0=100`. cc:361-:367
// `dump_file_cache_detail_params[]` — V1_cmds `params1=sha256_prefix
// def1_null=1` (PT_STRING, nullptr default, cc:363-:364; the help
// literals "number of cache entries to dump (default 100; -1 for
// all)" cc:356 / "SHA256 hex prefix of the cache entry" cc:364 have
// no landed Parameter slot — pinned here, same help-slot ruling as
// row 17z, deviation row 18a).
// ==================================================================
const DUMP_FILE_CACHE_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("max_entries"), ptype: PtType::PtInt, deflt: Some("100") }, // cc:355
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                       // cc:358
];
const DUMP_FILE_CACHE_DETAIL_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("sha256_prefix"), ptype: PtType::PtString, deflt: None },   // cc:363
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                       // cc:366
];

/// module.h:65-:73 `struct Command { name; LuaCFunction func;
/// const Parameter* params; help; bool can_run_in_parallel = false;
/// }` — `LuaCFunction = int(*)(lua_State*)` (module.h:63). No
/// lua_State value exists in the Rust tree: the func slot lands as a
/// PRESENCE bool over the two documented seam-shaped bodies above
/// (deviation row 18a: the V1 `fp0=1 fp1=1` pins liveness ONLY; the
/// const table NEVER calls through). can_run_in_parallel keeps the
/// module.h:72 default false on every row (no C initializer sets it).
pub struct CommandRecord {
    pub name: Option<&'static str>,
    pub func_present: bool,
    pub params: Option<&'static [Parameter; 2]>,
    pub help: &'static str,
    pub can_run_in_parallel: bool,
}

/// cc:369-:376 `static const Command file_inspect_cmds[]` — 2 rows +
/// the `{ nullptr, nullptr, nullptr, nullptr }` terminator (V1
/// `cmd0=dump_file_cache cmd1=dump_file_cache_detail cmd2_null=1`;
/// the params readback V1 `n=2 params0=... params1=...`).
pub const FMOD_COMMANDS: [CommandRecord; 3] = [
    CommandRecord {
        name: Some("dump_file_cache"), // cc:371
        func_present: true,            // -> dump_file_cache above
        params: Some(&DUMP_FILE_CACHE_PARAMS),
        help: "dump file cache summary (default 100 entries; optional row count arg, -1 for all)", // cc:372
        can_run_in_parallel: false,
    },
    CommandRecord {
        name: Some("dump_file_cache_detail"), // cc:373
        func_present: true,                   // -> dump_file_cache_detail above
        params: Some(&DUMP_FILE_CACHE_DETAIL_PARAMS),
        help: "dump details for a file cache entry by SHA256 prefix", // cc:374
        can_run_in_parallel: false,
    },
    CommandRecord {
        name: None, // cc:375 the null terminator row
        func_present: false,
        params: None,
        help: "",
        can_run_in_parallel: false,
    },
];

/// cc:378-:379 `get_commands() -> file_inspect_cmds` (a separate
/// impl block keeps the h:74-:77 getter group adjacent in reading
/// order to its C spot after the commands table).
impl FileIdModule {
    pub fn get_commands(&self) -> &'static [CommandRecord; 3] {
        &FMOD_COMMANDS
    }
}

