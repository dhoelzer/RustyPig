//! Literal port of `file_api/file_stats.{h,cc}` (file-processing stats
//! snapshot collection). Ported from the VERBATIM C as pinned by
//! `tools/fstats_harness` (upstream `file_api/test/file_stats_test.cc`
//! gate + 65-line probe transcript).
//!
//! Layout facts pinned by the transcript:
//!   - `FileStats` is all-PegCount with NO padding: `file_stats_sum`
//!     walks it as a flat array of NFLAT = 22550 slots
//!     (files/sigs/data: 3 * 1025 * 2, verdicts: 2 * 7,
//!     by-proto: 2 * 8193).
//!   - the render loops cover only `i < FILE_ID_MAX` (1024): index 1024
//!     (the extra slot) is summed by `file_stats_sum` but never seen by
//!     `file_stats_collect` (FLATSUM1=70 vs totals excluding it).
//!
//! C file statics (`file_totals`, thread-locals `file_counts`,
//! `file_stats`) are modeled as a driver-owned [`FileStatsEnv`], same
//! discipline as other harness-backed ports.
use crate::framework::counts::PegCount;
use crate::utils::stats::snapshot::{Builder, DynamicStatsPolicy, Group, Snapshot, Value};

/// file_api.h:118
pub const FILE_ID_MAX: usize = 1024;
/// file_stats.h:29
pub const MAX_PROTOCOL_ORDINAL: usize = 8192;
/// file_api.h FileVerdict enumerator count (UNKNOWN..STOP_CAPTURE)
pub const FILE_VERDICT_MAX: usize = 7;

/// C `struct FileStats` (file_stats.h). Field order is load-bearing:
/// `file_stats_sum` flat-adds the C struct in declaration order over
/// exactly [`flat_len`] slots.
#[derive(Clone, Debug, PartialEq)]
pub struct FileStats {
    pub files_processed: Vec<[PegCount; 2]>,
    pub signatures_processed: Vec<[PegCount; 2]>,
    pub verdicts_type: Vec<PegCount>,
    pub verdicts_signature: Vec<PegCount>,
    pub files_by_proto: Vec<PegCount>,
    pub signatures_by_proto: Vec<PegCount>,
    pub data_processed: Vec<[PegCount; 2]>,
}

impl Default for FileStats {
    fn default() -> Self {
        FileStats {
            files_processed: vec![[0; 2]; FILE_ID_MAX + 1],
            signatures_processed: vec![[0; 2]; FILE_ID_MAX + 1],
            verdicts_type: vec![0; FILE_VERDICT_MAX],
            verdicts_signature: vec![0; FILE_VERDICT_MAX],
            files_by_proto: vec![0; MAX_PROTOCOL_ORDINAL + 1],
            signatures_by_proto: vec![0; MAX_PROTOCOL_ORDINAL + 1],
            data_processed: vec![[0; 2]; FILE_ID_MAX + 1],
        }
    }
}

impl FileStats {
    /// sizeof(FileStats)/sizeof(PegCount) — pinned to 22550 by the
    /// transcript (LAYOUT nfl=22550).
    pub fn flat_len() -> usize {
        (FILE_ID_MAX + 1) * 2 * 3 + FILE_VERDICT_MAX * 2 + (MAX_PROTOCOL_ORDINAL + 1) * 2
    }

    /// Sum over the flat walk (test mirror of the printf FLATSUM rows).
    pub fn flat_sum(&self) -> u128 {
        let mut s = 0u128;
        for f in [
            &self.files_processed,
            &self.signatures_processed,
            &self.data_processed,
        ] {
            for pair in f {
                s += (pair[0] + pair[1]) as u128;
            }
        }
        for f in [&self.verdicts_type, &self.verdicts_signature] {
            s += f.iter().sum::<PegCount>() as u128;
        }
        for f in [&self.files_by_proto, &self.signatures_by_proto] {
            s += f.iter().sum::<PegCount>() as u128;
        }
        s
    }

    fn field_pairs_mut(&mut self) -> [&mut Vec<[PegCount; 2]>; 3] {
        [
            &mut self.files_processed,
            &mut self.signatures_processed,
            &mut self.data_processed,
        ]
    }

    fn field_scalars_mut(&mut self) -> [&mut Vec<PegCount>; 4] {
        [
            &mut self.verdicts_type,
            &mut self.verdicts_signature,
            &mut self.files_by_proto,
            &mut self.signatures_by_proto,
        ]
    }
}

/// C `struct FileCounts` (file_stats.h). All 31 PegCount members named
/// in C order; only the two buffer members are touched by ported fns
/// (file_counts_update_buffers), the rest exist for layout parity.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FileCounts {
    pub files_total: PegCount,
    pub file_data_total: PegCount,
    pub cache_add_fails: PegCount,
    pub files_over_flow_limit_not_processed: PegCount,
    pub max_concurrent_files_per_flow: PegCount,
    pub file_buffers_max: PegCount,
    pub file_buffers_in_use: PegCount,
    pub files_buffered_total: PegCount,
    pub files_released_total: PegCount,
    pub files_freed_total: PegCount,
    pub files_captured_total: PegCount,
    pub file_memcap_failures_total: PegCount,
    pub file_reserve_failures: PegCount,
    pub file_size_min: PegCount,
    pub file_size_max: PegCount,
    pub file_within_packet: PegCount,
    pub file_buffers_used_max: PegCount,
    pub file_buffers_allocated_total: PegCount,
    pub file_buffers_freed_total: PegCount,
    pub file_buffers_released_total: PegCount,
    pub file_buffers_free_errors: PegCount,
    pub file_buffers_release_errors: PegCount,
    pub file_sig_depth_exceeded: PegCount,
    pub file_lookup_timeouts: PegCount,
    pub file_cache_hits: PegCount,
    pub file_cache_misses: PegCount,
    pub file_cache_total_entries: PegCount,
    pub file_cache_full: PegCount,
    pub file_cache_failures: PegCount,
    pub file_cache_max_entries: PegCount,
    /// internal only; not in file_pegs[]
    pub file_memcap_failures_reserve: PegCount,
}

/// Witness seams for the FileCapture/FileService parts of
/// `file_stats_collect` (the C harness links witness definitions,
/// mirroring the upstream test's own witnesses).
pub trait FileStatsHooks {
    /// `FileService::is_file_signature_enabled()`
    fn is_file_signature_enabled(&self) -> bool;
    /// `file_type_name(uint32_t)` (file_config.cc reads the live
    /// FileConfig; harness witnesses return "" for unnamed ids)
    fn file_type_name(&self, id: u32) -> String;
    /// `FileCapture::collect_mem_usage(builder, group)` — Builder is
    /// unused by the witness bodies the transcripts pin, so it is
    /// omitted from the seam.
    fn collect_mem_usage(&self, group: &mut Group) {
        let _ = group;
    }
    /// `FileService::collect_cache_usage(builder, group)`
    fn collect_cache_usage(&self, group: &mut Group) {
        let _ = group;
    }
    /// `FileCapture::get_buffers_max()` / `get_buffers_in_use()`
    fn buffers_max(&self) -> i64;
    fn buffers_in_use(&self) -> i64;
}

/// C file statics + thread-locals, driver-owned.
#[derive(Default)]
pub struct FileStatsEnv {
    /// file-static `FileStats file_totals;`
    pub file_totals: FileStats,
    /// THREAD_LOCAL `FileCounts file_counts;`
    pub file_counts: FileCounts,
    /// THREAD_LOCAL `FileStats* file_stats;` — C `nullptr` before init.
    /// C `file_stats_term` FREES without nulling (dangling); Rust
    /// models that as `None` (documented deviation — reproducing the
    /// dangling deref in `file_stats_clear` is UB, the harness pinned
    /// it observationally via `TERM dangling=1`).
    pub file_stats: Option<Box<FileStats>>,
}

/// `file_stats_init`: `file_stats = (FileStats*)snort_calloc(...)`
pub fn file_stats_init(env: &mut FileStatsEnv) {
    env.file_stats = Some(Box::default());
}

/// `file_stats_term`: `snort_free(file_stats)` — see env notes.
pub fn file_stats_term(env: &mut FileStatsEnv) {
    env.file_stats = None;
}

/// `file_counts_update_buffers`
pub fn file_counts_update_buffers(env: &mut FileStatsEnv, hooks: &dyn FileStatsHooks) {
    env.file_counts.file_buffers_max = hooks.buffers_max() as PegCount;
    env.file_counts.file_buffers_in_use = hooks.buffers_in_use() as PegCount;
}

/// `file_stats_sum`: flat-add `file_stats` into `file_totals` over
/// NFLAT slots, then memset the per-thread stats to zero. Rust adds
/// per-field in declaration order (identical slot order: the C struct
/// is all-u64 with no padding).
pub fn file_stats_sum(env: &mut FileStatsEnv) {
    let stats = match env.file_stats.as_mut() {
        Some(s) => s,
        None => return,
    };
    let totals = &mut env.file_totals;
    for (t, s) in totals
        .field_pairs_mut()
        .into_iter()
        .zip(stats.field_pairs_mut())
    {
        for (tp, sp) in t.iter_mut().zip(s.iter()) {
            tp[0] += sp[0];
            tp[1] += sp[1];
        }
    }
    for (t, s) in totals
        .field_scalars_mut()
        .into_iter()
        .zip(stats.field_scalars_mut())
    {
        for (tv, sv) in t.iter_mut().zip(s.iter()) {
            *tv += *sv;
        }
    }
    **stats = FileStats::default(); // C memset(file_stats, 0, ...)
}

/// `file_stats_clear`
pub fn file_stats_clear(env: &mut FileStatsEnv) {
    env.file_counts = FileCounts::default();
    env.file_totals = FileStats::default();
    // C memsets through the (possibly dangling) thread-local pointer;
    // Rust clears the live Option only — see env notes.
    if let Some(s) = env.file_stats.as_mut() {
        **s = FileStats::default();
    }
}

/// `file_stats_collect(builder, policy)` — `builder` borrows the
/// snapshot; `file_totals` is read from env.
pub fn file_stats_collect(
    env: &FileStatsEnv,
    snapshot: &mut Snapshot,
    policy: &DynamicStatsPolicy,
    hooks: &dyn FileStatsHooks,
) {
    let file_totals = &env.file_totals;
    let mut processed_total: [u64; 2] = [0, 0];
    let mut processed_data_total: [u64; 2] = [0, 0];
    let mut processed_sig_total: [u64; 2] = [0, 0];
    let mut check_total: u64 = 0;
    let mut check_sig_total: u64 = 0;

    // C loops index with i; the check sums never use i beyond the
    // slice bound, so iterate the slices directly.
    for p in file_totals.files_processed.iter().take(FILE_ID_MAX) {
        check_total += p[0];
        check_total += p[1];
    }
    for p in file_totals.signatures_processed.iter().take(FILE_ID_MAX) {
        check_sig_total += p[0];
        check_sig_total += p[1];
    }

    let include_signatures = hooks.is_file_signature_enabled() && check_sig_total != 0;

    let columns: Vec<String> = if include_signatures {
        ["Type", "TypeDn", "TypeUp", "SigDn", "SigUp", "BytesDn", "BytesUp"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        ["Type", "TypeDn", "TypeUp", "BytesDn", "BytesUp"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    };

    let mut rows: Vec<Vec<Value>> = Vec::with_capacity(FILE_ID_MAX);

    // C declares processed_*[] uninitialized, then re-zeroes them
    // right before the render loop; Rust initializes once at decl.
    if check_total != 0 || policy.include_zeros {
        for i in 0..FILE_ID_MAX {
            let mut type_name = hooks.file_type_name(i as u32);

            // C: `bool status = false;` then unconditional if/else
            // assignment; Rust computes directly (same short-circuit).
            let status = if include_signatures {
                file_totals.files_processed[i][0] != 0
                    || file_totals.files_processed[i][1] != 0
                    || file_totals.signatures_processed[i][0] != 0
                    || file_totals.signatures_processed[i][1] != 0
            } else {
                file_totals.files_processed[i][0] != 0
                    || file_totals.files_processed[i][1] != 0
            };

            if !type_name.is_empty() && (status || policy.include_zeros) {
                type_name.push('(');
                type_name.push_str(&i.to_string()); // C std::to_string(i)
                type_name.push(')');
                if include_signatures {
                    rows.push(vec![
                        Value::Str(type_name),
                        Value::U64(file_totals.files_processed[i][0]),
                        Value::U64(file_totals.files_processed[i][1]),
                        Value::U64(file_totals.signatures_processed[i][0]),
                        Value::U64(file_totals.signatures_processed[i][1]),
                        Value::U64(file_totals.data_processed[i][0]),
                        Value::U64(file_totals.data_processed[i][1]),
                    ]);
                } else {
                    rows.push(vec![
                        Value::Str(type_name),
                        Value::U64(file_totals.files_processed[i][0]),
                        Value::U64(file_totals.files_processed[i][1]),
                        Value::U64(file_totals.data_processed[i][0]),
                        Value::U64(file_totals.data_processed[i][1]),
                    ]);
                }
                processed_total[0] += file_totals.files_processed[i][0];
                processed_total[1] += file_totals.files_processed[i][1];
                processed_data_total[0] += file_totals.data_processed[i][0];
                processed_data_total[1] += file_totals.data_processed[i][1];
                if include_signatures {
                    processed_sig_total[0] += file_totals.signatures_processed[i][0];
                    processed_sig_total[1] += file_totals.signatures_processed[i][1];
                }
            }
        }
    }

    // C local `stats::Group group; group.name = "file stats";`: a
    // local Group value moved into the Section only at the end.
    let mut group = Group {
        name: "file stats".to_string(),
        ..Default::default()
    };

    if !rows.is_empty() {
        // C statics Builder::table/row on the LOCAL group (no Snapshot
        // involvement until the section is appended below).
        let table = Builder::table(&mut group, "file stats", columns, false);
        for row in rows.iter_mut() {
            Builder::row(table, std::mem::take(row));
        }
        if include_signatures {
            Builder::row(
                table,
                vec![
                    Value::Str("Total".to_string()),
                    Value::U64(processed_total[0]),
                    Value::U64(processed_total[1]),
                    Value::U64(processed_sig_total[0]),
                    Value::U64(processed_sig_total[1]),
                    Value::U64(processed_data_total[0]),
                    Value::U64(processed_data_total[1]),
                ],
            );
        } else {
            Builder::row(
                table,
                vec![
                    Value::Str("Total".to_string()),
                    Value::U64(processed_total[0]),
                    Value::U64(processed_total[1]),
                    Value::U64(processed_data_total[0]),
                    Value::U64(processed_data_total[1]),
                ],
            );
        }
    }

    // comment-only #if 0 block in C (legacy verdict tables) not ported.

    hooks.collect_mem_usage(&mut group);
    hooks.collect_cache_usage(&mut group);

    if group.tables.is_empty() && group.counters.is_empty() {
        return;
    }

    let mut builder = Builder::new(snapshot);
    let section = builder.section("File Statistics");
    section.groups.push(group);
}
