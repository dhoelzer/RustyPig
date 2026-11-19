//! Row 17u: `src/file_api/file_config.{h,cc}` — the config-aggregator
//! TU (80 + 128 lines at fe29cbe; zero TEST_CASEs, zero `#ifdef
//! UNIT_TEST` fragments, PLAN 2/4: the 20-line vectors.txt arms
//! D/N/T/F/G/M/S are the only oracles — no replay tests in this
//! phase, task gate).
//!
//! What this module owns:
//!   * the CANONICAL home of the 11 `DEFAULT_*` macros +
//!     `FILE_ID_NAME`/`FILE_ID_HELP` (h:30-:43). The three-way const
//!     dup (file_cache.rs:104-:109 trio / file_lib.rs:801-:812 seven /
//!     this table) collapses here: the siblings keep their old names
//!     as `pub use` re-exports so every existing binding stays green
//!     (tests/ bindings verified by grep before moving:
//!     fctx_parity_test.rs:59-:61 imports through file_lib,
//!     fcache_parity_test.rs:45 globs file_cache).
//!   * the free [`file_type_name`] (cc:80-:87 — the null-conf arm
//!     answers **"NA"**, cc:85-:86, probe F6 `s=NA eq_na=1`) and the
//!     [`get_file_config`] chain shape (cc:89-:100) beside the seam
//!     `FileEnvLite::get_file_config()` that already resolves it.
//!   * the two `snort::`-namespace API shims (cc:102-:128) whose null
//!     arms (`ids_set.reset()` / silent no-op — probe M4/M2) are
//!     observable contract for the ips_options consumers
//!     (ips_file_type.cc:196/:205/:214, ips_file_meta.cc:129, PLAN 6).
//!
//! NOT duplicated here: the C `class FileConfig` (h:45-:76) field set
//! is already ported as `FileConfigLite` (file_lib.rs:820-:848, 17q) —
//! including the private `FileIdentifier fileIdentifier` member
//! (h:75 -> `file_identifier`, file_lib.rs:846-:847) — and its
//! hand-written `Default` (file_lib.rs:850-:873) is the D_defaults
//! transcription. A parallel `FileConfig` struct here would fork that
//! initializer list; this module instead carries the consts the
//! Default cites. `FileConfigView` (file_cache.rs:319-:343) STAYS
//! untouched either — the 17p-pinned by-value `PacketView::conf`
//! contract (file_cache.rs:266, PLAN 8 item 5).
//!
//! R1 (derive-Default trap, PLAN 9): 10 fields carry non-zero C
//! in-class initializers (PLAN 7b table, the consts below) —
//! `#[derive(Default)]` would silently zero every depth and
//! depth-fail every armed ladder. Hand-written Defaults stay.
use super::file_identifier::{FileIdErrorSink, FileMeta, FILE_ID_MAX};
use super::file_lib::{FileConfigLite, FileEnvLite};
use std::cell::RefCell;
use std::rc::Rc;

// ==================================================================
// The macro table — file_config.h:30-:43 at fe29cbe (the three-way
// dup's canonical home; PLAN R5: line cites here, refresh drift only
// in comments this row touches). Capture numerals pinned as written:
// h:35 `100 // 100 MiB` is a RAW MiB count, no unit multiply
// anywhere (PLAN R2 / probe D_defaults `cap_mem=100`).
// ==================================================================

/// file_config.h:30 `#define DEFAULT_FILE_TYPE_DEPTH 1460`
/// (D_defaults `ftd=1460`)
pub const DEFAULT_FILE_TYPE_DEPTH: i64 = 1460;
/// file_config.h:31 `#define DEFAULT_FILE_SIGNATURE_DEPTH 10485760 /*10 Mbytes*/`
/// (D_defaults `sig_depth=10485760`)
pub const DEFAULT_FILE_SIGNATURE_DEPTH: i64 = 10_485_760; // 10 MiB
/// file_config.h:32 `#define DEFAULT_FILE_SHOW_DATA_DEPTH 100`
/// (D_defaults `show_depth=100`)
pub const DEFAULT_FILE_SHOW_DATA_DEPTH: i64 = 100;
/// file_config.h:33 `#define DEFAULT_FILE_BLOCK_TIMEOUT 86400 /*1 day*/`
/// (D_defaults `blk_to=86400`)
pub const DEFAULT_FILE_BLOCK_TIMEOUT: i64 = 86400;
/// file_config.h:34 `#define DEFAULT_FILE_LOOKUP_TIMEOUT 2 /*2 seconds*/`
/// (D_defaults `lookup=2`)
pub const DEFAULT_FILE_LOOKUP_TIMEOUT: i64 = 2;
/// file_config.h:35 `#define DEFAULT_FILE_CAPTURE_MEM 100 // 100 MiB`
/// (RAW MiB count, PLAN R2 — never "converted"; D_defaults `cap_mem=100`)
pub const DEFAULT_FILE_CAPTURE_MEM: i64 = 100;
/// file_config.h:36 `#define DEFAULT_FILE_CAPTURE_MAX_SIZE 1048576 // 1 MiB`
/// (D_defaults `cap_max=1048576`)
pub const DEFAULT_FILE_CAPTURE_MAX_SIZE: i64 = 1_048_576;
/// file_config.h:37 `#define DEFAULT_FILE_CAPTURE_MIN_SIZE 0 // 0`
/// (zero arm, D_defaults `cap_min=0`)
pub const DEFAULT_FILE_CAPTURE_MIN_SIZE: i64 = 0;
/// file_config.h:38 `#define DEFAULT_FILE_CAPTURE_BLOCK_SIZE 32768 // 32 KiB`
/// (D_defaults `cap_blk=32768`)
pub const DEFAULT_FILE_CAPTURE_BLOCK_SIZE: i64 = 32_768;
/// file_config.h:39 `#define DEFAULT_MAX_FILES_CACHED 65536`
/// (D_defaults `max_cached=65536`)
pub const DEFAULT_MAX_FILES_CACHED: i64 = 65536;
/// file_config.h:40 `#define DEFAULT_MAX_FILES_PER_FLOW 128`
/// (D_defaults `max_per_flow=128`; the C FIELD type is uint64_t, h:66,
/// vs max_files_cached int64_t, h:65 — asymmetry kept, PLAN R2)
pub const DEFAULT_MAX_FILES_PER_FLOW: u64 = 128;

/// file_config.h:42 `#define FILE_ID_NAME "file_inspect"` — the
/// FileIdModule config string (file_module row consumes it;
/// N_names `name=file_inspect name_eq=1`)
pub const FILE_ID_NAME: &str = "file_inspect";
/// file_config.h:43 `#define FILE_ID_HELP "configure file inspection"`
/// (N_names `help_eq=1`; these are C literals for the parser/module
/// layer — `&'static str` per PLAN R3)
pub const FILE_ID_HELP: &str = "configure file inspection";

/// `std::string file_type_name(uint32_t id)` — the FREE GLOBAL
/// (file_config.cc:80-:87), NOT the member (the member is
/// `FileConfigLite::file_type_name`, file_lib.rs:883-:894, and has NO
/// null path — PLAN R6: free arms F5/F6 resolve through the seam,
/// member arms T1-T4 never do). C resolves the config through the two
/// singletons (`get_file_config()` cc:82); the Rust chain resolves
/// through `FileEnvLite::get_file_config()` (file_lib.rs:1141-:1146,
/// the seam the inline F5/NA resolutions at file_lib.rs:2772-:2775 and
/// file_flows.rs:226-:229 already use — those call sites stay as the
/// 17q/17r pinned them; this is the named-home version).
/// conf hit -> the cc:83-:84 member path; conf null -> **"NA"**
/// (cc:85-:86, F6 `s=NA eq_na=1`). Deviation note: C would deref a
/// null conf (UB); the port keeps the harness-pinned "NA" answer.
pub fn file_type_name(env: &FileEnvLite, id: u32) -> String {
    match env.get_file_config() {
        Some(conf) => conf.borrow().file_type_name(id), // cc:83-:84
        None => "NA".to_string(),                       // cc:85-:86
    }
}

/// `FileConfig* get_file_config(const SnortConfig* sc = nullptr)`
/// (file_config.cc:89-:100) as one named chain, mirroring the C order:
/// `sc` null -> `SnortConfig::get_conf()` (:91-:92);
/// `InspectorManager::get_file_inspector(sc)` cast (:94); `fi ?
/// fi->config : nullptr` (:96-:99). Both singleton lookups are
/// harness-resolved in the port — `FileEnvLite::get_file_config()` is
/// that chain's single seam (row 17q, file_lib.rs:1141-:1146), and
/// the G-arm contract rides it: armed seam -> the config (G1/G2
/// `is_harness_conf=1`), inspector-null toggle -> `None` (G3
/// `conf_null_noarg=1 conf_null_sc=1` for BOTH call shapes: the Rust
/// seam has no `sc` arm — `get_file_config(&sc)` and `get_file_config()`
/// collapse to the same None answer, which is what G3 pins).
pub fn get_file_config(env: &FileEnvLite) -> Option<Rc<RefCell<FileConfigLite>>> {
    env.get_file_config()
}

/// C's global `ParseError` sink (file_identifier.cc:195-:198
/// `file type: rule id %u found duplicate`) stands for the null model
/// here: no pinned vector arms a duplicate through the seam path
/// (M1 arms fresh id 12, M2 the null conf never reaches add_file_id,
/// D_forwarders arms fresh 7), so the shims answer quietly. A parser
/// row that surfaces ParseError re-arms a real sink through the
/// `process_file_rule` parameter instead (1:1 with C's error arm).
struct NullParseError;
impl FileIdErrorSink for NullParseError {
    fn parse_error(&mut self, _msg: &str) {}
}

// ==================================================================
// The two snort:: API shims (file_config.cc:102-:128). C exports take
// `std::string` BY VALUE and `SnortConfig*` — the cppcheck-suppress
// comments at cc:105 and cc:115-:119 pin those declarations (R3: do
// not "fix", do not read the by-value params as refs). Rust
// deviation: `type`/`version`/`ids_set` borrow and the `sc` parameter
// becomes `env` (the threaded seam, crate-wide), while the OBSERVABLE
// null arms ride 1:1 — they are contract for the ips_options call
// sites (PLAN 6).
// ==================================================================

/// `snort::get_magic_rule_ids_from_type(const std::string& type,
/// const std::string& version, FileTypeBitSet& ids_set,
/// SnortConfig* sc)` (file_config.cc:104-:113). Conf hit -> the
/// member forward cc:110 (the M3 version-quoting semantics — query
/// `""` matches any version, query `"v1"` against unquoted stored
/// `"v1"` misses — live in `FileIdentifier::get_magic_rule_ids_from_
/// type`, fid row); conf null -> `ids_set.reset()` (cc:112) — the M4
/// sentinel pin (`pre_count=3 pre=111 post_count=0 post=000`: bits
/// 0/7/1023 set before the null call, all cleared after). `ids_set` is
/// the bitset<FILE_ID_MAX> word form (file_api.h:118-:119 typedef via
/// the fid row's `&mut [u64; FILE_ID_MAX / 64]`).
pub fn get_magic_rule_ids_from_type(
    env: &FileEnvLite,
    r#type: &str,
    version: &str,
    ids_set: &mut [u64; FILE_ID_MAX / 64],
) {
    // cc:108 `const FileConfig* conf = get_file_config(sc);`
    match env.get_file_config() {
        // cc:109-:110 conf -> member forward (read-only: &self arms)
        Some(conf) => conf.borrow().get_magic_rule_ids_from_type(r#type, version, ids_set),
        // cc:111-:112 `else ids_set.reset();`
        None => {
            for w in ids_set.iter_mut() {
                *w = 0;
            }
        }
    }
}

/// `snort::set_rule_id_from_type(SnortConfig* sc, uint64_t id,
/// std::string type, std::string file_category, std::string
/// file_version, std::vector<std::string> file_groups)`
/// (file_config.cc:115-:127): conf hit -> construct
/// `FileMeta rule(id, type, file_category, file_version, file_groups)`
/// (cc:124; the C FileMeta(type_id, ...) ctor sets exactly those five
/// fields — `rev` stays the in-class 0, file_identifier.h:43) ->
/// `conf->process_file_rule(rule)` (cc:125 -> add_file_id); conf null
/// -> SILENT NO-OP, no witness (cc:122 guard; M2: id 13 table stays
/// empty, `silent_noop=1 rule13null=1`, while M1's fresh id 12 arms
/// and reads back through the seam table + free name path). The C
/// `uint64_t id` narrows into FileMeta::id (uint32_t, h:44) exactly as
/// the C aggregate init does — kept explicit.
pub fn set_rule_id_from_type(
    env: &FileEnvLite,
    id: u64,
    r#type: String,
    file_category: String,
    file_version: String,
    file_groups: Vec<String>,
) {
    if let Some(conf) = env.get_file_config() {
        // cc:124 (field order per the C ctor, file_identifier.h:32-:35)
        let rule = FileMeta {
            rev: 0, // file_identifier.h:43 (the C ctor never touches rev)
            id: id as u32,
            r#type,
            category: file_category,
            version: file_version,
            groups: file_groups,
        };
        // cc:125 -> FileConfig::process_file_rule -> add_file_id
        let mut sink = NullParseError;
        conf.borrow_mut().process_file_rule(&rule, &mut sink);
    }
    // cc:122: conf null -> nothing happens, nothing printed
}

// ==================================================================
// LEFT-OPEN (named, per task gate):
//   * C's h:75 private `FileIdentifier fileIdentifier` IS ported
//     (file_api/file_identifier.rs, fid row) and rides
//     `FileConfigLite::file_identifier` (file_lib.rs:846-:847), so
//     the four member forwarders (find_file_type_id h:52/cc:41-:45,
//     process_file_rule h:51/cc:48-:51, get_rule_from_id
//     h:48/cc:53-:56, get_magic_rule_ids_from_type h:49-:50/
//     cc:58-:62) are wired DIRECTLY on FileConfigLite (the struct
//     carrying the member), not on a new FileConfig struct here — the
//     D_* `rule_id=7 rule_type=exe` / `find_empty_trie=65535
//     ctx_null=1` and M1-M4 arms resolve through them.
//   * `sizeof(FileConfig)` (probe CONF line `sizeof_FileConfig=
//     131360` — the embedded-FileIdentifier blob size): no ported
//     consumer reads it; skipped by design (a Rust layout pin would
//     re-derive the fid row's internals).
//   * `file_inspect.h:36` `FileConfig* config` — the FileInspect
//     member the cc:94-:97 cast reads — stays the
//     `FileEnvLite::file_config` slot (17q) until the file_inspect
//     row ports the inspector itself.
//   * `FileContext.config` type duality (two Rc config types coexist
//     at file_lib.rs:1301-:1309 — the doc comment there names it):
//     PLAN 8 item 6 keeps it open; swapping the 17q FileConfigView
//     for FileConfigLite re-arms every pinned 17p/17r vector.
//   * file_stats.rs:22 mirrors FILE_ID_MAX a second time (fid row's
//     turf); not touched by this row.
// ==================================================================
