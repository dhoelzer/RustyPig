// Whole-transcript replay of tools/fstats_harness/vectors.txt (C
// probe includes file_stats.cc VERBATIM, mirrors the upstream test's
// witness style) against the Rust port, plus faithful translations of
// the 4 upstream [file_stats] TEST_CASEs.
use snort3::file_api::file_stats::*;
use snort3::utils::stats::snapshot::{DynamicStatsPolicy, Group, Snapshot, Value};

#[derive(Default)]
struct W {
    name_file_type: bool,
    name_zero_file_type: bool,
    name_last_file_type: bool,
    use_file_cache: bool,
    file_cache_entries: u64,
    use_capture_counter: bool,
    capture_mem_bytes: u64,
    sig_enabled: bool,
}

impl FileStatsHooks for W {
    fn is_file_signature_enabled(&self) -> bool {
        self.sig_enabled
    }
    fn file_type_name(&self, id: u32) -> String {
        if self.name_file_type && id == 1 {
            return "TEST".into();
        }
        if self.name_zero_file_type && id == 2 {
            return "ZERO".into();
        }
        if self.name_last_file_type && id == FILE_ID_MAX as u32 {
            return "LAST".into();
        }
        String::new()
    }
    fn collect_mem_usage(&self, group: &mut Group) {
        if self.use_capture_counter {
            // C: builder.counter(group, "Capture memcap", capture_mem_bytes)
            snort3::utils::stats::snapshot::Builder::counter(
                group,
                "Capture memcap",
                Value::U64(self.capture_mem_bytes),
            );
        }
    }
    fn collect_cache_usage(&self, group: &mut Group) {
        if self.use_file_cache {
            snort3::utils::stats::snapshot::Builder::counter(
                group,
                "File cache entries",
                Value::U64(self.file_cache_entries),
            );
        }
    }
    fn buffers_max(&self) -> i64 {
        41
    } // witness constant
    fn buffers_in_use(&self) -> i64 {
        7
    }
}

fn vstr(v: &Value) -> String {
    match v {
        Value::Mono => "x".to_string(),
        Value::Bool(b) => {
            if *b {
                "b1".to_string()
            } else {
                "b0".to_string()
            }
        }
        Value::I64(i) => format!("i:{}", i),
        Value::U64(n) => format!("n:{}", n),
        Value::F64(d) => format!("d:{}", d),
        Value::Str(s) => format!("s:{}", s),
    }
}

fn dump(s: &Snapshot, got: &mut Vec<String>) {
    got.push(format!("SECCTIONS={}", s.sections.len()));
    for sec in &s.sections {
        got.push(format!("SEC {} ng={}", sec.name, sec.groups.len()));
        for g in &sec.groups {
            got.push(format!(
                " GRP {} nc={} nt={}",
                g.name,
                g.counters.len(),
                g.tables.len()
            ));
            for c in &g.counters {
                got.push(format!("  CTR {}={}", c.get_name(), vstr(&c.value)));
            }
            for t in &g.tables {
                got.push(format!(
                    "  TBL {} {} fc={}",
                    t.name,
                    t.columns.len(),
                    if t.first_column_has_colon {
                        1
                    } else {
                        0
                    }
                ));
                for col in &t.columns {
                    got.push(format!("   COL {}", col));
                }
                for row in &t.rows {
                    let cells: Vec<String> = row.iter().map(vstr).collect();
                    got.push(format!("   ROW {}", cells.join(" ")));
                }
            }
        }
    }
}

fn collect(env: &FileStatsEnv, w: &W, policy: DynamicStatsPolicy) -> Snapshot {
    let mut s = Snapshot::default();
    file_stats_collect(env, &mut s, &policy, w);
    s
}

#[test]
#[allow(clippy::too_many_lines)]
fn fstats_transcript_replay() {
    let mut got: Vec<String> = Vec::new();

    got.push(format!(
        "LAYOUT nfl={} nfc={}",
        FileStats::flat_len(),
        std::mem::size_of::<FileCounts>() / 8
    ));

    // Z0
    let w = W::default();
    let mut env = FileStatsEnv::default();
    file_stats_clear(&mut env);
    dump(&collect(&env, &w, DynamicStatsPolicy::default()), &mut got);

    // Z1
    let w = W {
        use_capture_counter: true,
        capture_mem_bytes: 99,
        use_file_cache: true,
        file_cache_entries: 5,
        ..Default::default()
    };
    dump(&collect(&env, &w, DynamicStatsPolicy::default()), &mut got);

    // S1
    let w = W {
        name_file_type: true,
        name_last_file_type: true,
        ..Default::default()
    };
    // fresh env (C probe ran file_stats_clear() first)
    env = FileStatsEnv::default();
    file_stats_clear(&mut env);
    env.file_totals.files_processed[1][0] = 2;
    env.file_totals.files_processed[1][1] = 3;
    env.file_totals.data_processed[1][0] = 20;
    env.file_totals.data_processed[1][1] = 30;
    env.file_totals.files_processed[40][1] = 11;
    env.file_totals.files_processed[FILE_ID_MAX][0] = 4;
    assert_eq!(env.file_totals.flat_sum(), 70);
    got.push(format!("FLATSUM1={}", env.file_totals.flat_sum()));
    dump(&collect(&env, &w, DynamicStatsPolicy::default()), &mut got);

    // S2: file_totals carry S1's values (no clear; sigs off in S1)
    let w = W {
        name_file_type: true,
        sig_enabled: true,
        ..Default::default()
    };
    env.file_totals.signatures_processed[1][0] = 9;
    env.file_totals.signatures_processed[5][0] = 7;
    dump(&collect(&env, &w, DynamicStatsPolicy::default()), &mut got);

    // S3
    let w = W {
        name_file_type: true,
        name_zero_file_type: true,
        sig_enabled: true,
        ..Default::default()
    };
    dump(
        &collect(
            &env,
            &w,
            DynamicStatsPolicy {
                include_zeros: true,
            },
        ),
        &mut got,
    );

    // S4: clear first; single file row; sigs enabled but sig total 0
    let w = W {
        name_file_type: true,
        sig_enabled: true,
        ..Default::default()
    };
    file_stats_clear(&mut env);
    env.file_totals.files_processed[1][0] = 1;
    dump(&collect(&env, &w, DynamicStatsPolicy::default()), &mut got);

    // S6 (buffers; reset_witnesses + file_stats_clear in probe)
    let w = W::default();
    file_stats_clear(&mut env);
    file_counts_update_buffers(&mut env, &w);
    got.push(format!(
        "BUFFERS max={} in_use={}",
        env.file_counts.file_buffers_max, env.file_counts.file_buffers_in_use
    ));
    file_stats_clear(&mut env);
    got.push(format!(
        "FLATSUMEND={}",
        env.file_totals.flat_sum()
    ));

    // S5 (init/sum/term; NOTE: probe order had S6 BEFORE S5)
    file_stats_init(&mut env);
    got.push(format!(
        "INIT notnull={}",
        if env.file_stats.is_some() {
            1
        } else {
            0
        }
    ));
    if let Some(st) = env.file_stats.as_mut() {
        st.files_processed[40][1] = 6;
        st.files_processed[1][0] = 8;
        st.data_processed[1][1] = 12;
    }
    file_stats_clear(&mut env);
    if let Some(st) = env.file_stats.as_mut() {
        st.files_processed[1][0] = 5;
    }
    file_stats_sum(&mut env);
    got.push(format!(
        "AFTER_SUM flat_totals={} flat_thread={}",
        env.file_totals.flat_sum(),
        env.file_stats.as_ref().map_or(0, |s| s.flat_sum())
    ));
    file_stats_sum(&mut env);
    got.push(format!(
        "AGAIN flat_totals={}",
        env.file_totals.flat_sum()
    ));
    got.push(format!(
        "PRETERM notnull={}",
        if env.file_stats.is_some() {
            1
        } else {
            0
        }
    ));
    file_stats_term(&mut env);
    // C leaves the global dangling (freed, non-null); Rust models the
    // freed C pointer as None — pinned observationally by the harness
    // (`TERM dangling=1`), Rust reports the modeled nullness.
    got.push(format!(
        "TERM dangling={}",
        if env.file_stats.is_some() {
            1
        } else {
            0
        }
    ));

    got.push("DONE".to_string());

    let want_bytes = include_bytes!("../tools/fstats_harness/vectors.txt");
    let want = String::from_utf8(want_bytes.to_vec()).expect("vectors utf8");
    let mut want_lines: Vec<String> = want
        .trim_end_matches('\n')
        .split('\n')
        .map(|s| s.to_string())
        .collect();

    // C TERM line printed the freed-pointer nullness (non-null after
    // free); Rust models the freed C pointer as None (0). Normalize
    // that one documented deviation line, then full byte compare.
    for l in want_lines.iter_mut() {
        if *l == "TERM dangling=1" {
            *l = "TERM dangling=0".to_string();
        }
    }
    assert_eq!(want_lines, got, "transcript replay mismatch");
}

// ---- upstream [file_stats] TEST_CASE translations ----

fn up_w(name_t: bool, name_z: bool, cache: bool, entries: u64) -> W {
    W {
        name_file_type: name_t,
        name_zero_file_type: name_z,
        use_file_cache: cache,
        file_cache_entries: entries,
        ..Default::default()
    }
}

#[test]
fn up_skips_totals_when_no_rows_renderable() {
    let env = FileStatsEnv::default(); // reset_file_stats()
    let w = up_w(false, false, false, 0);
    let s = collect(&env, &w, DynamicStatsPolicy::default());
    assert!(s.sections.is_empty());
}

#[test]
fn up_includes_cache_usage_without_file_rows() {
    let env = FileStatsEnv::default();
    let w = up_w(false, false, true, 1);
    let s = collect(&env, &w, DynamicStatsPolicy::default());
    assert_eq!(s.sections.len(), 1);
    let section = &s.sections[0];
    assert_eq!(section.name, "File Statistics");
    assert_eq!(section.groups.len(), 1);
    let group = &section.groups[0];
    assert_eq!(group.name, "file stats");
    assert!(group.tables.is_empty());
    assert_eq!(group.counters.len(), 1);
    assert_eq!(group.counters[0].get_name(), "File cache entries");
    assert_eq!(group.counters[0].value, Value::U64(1));
}

#[test]
fn up_includes_valid_rows_and_cache_without_zero_policy() {
    let mut env = FileStatsEnv::default();
    let w = up_w(true, true, true, 1);
    env.file_totals.files_processed[1][0] = 2;
    env.file_totals.files_processed[1][1] = 3;
    env.file_totals.data_processed[1][0] = 20;
    env.file_totals.data_processed[1][1] = 30;
    let s = collect(&env, &w, DynamicStatsPolicy::default());
    assert_eq!(s.sections.len(), 1);
    let group = &s.sections[0].groups[0];
    assert_eq!(group.tables.len(), 1);
    assert_eq!(group.counters.len(), 1);
    assert_eq!(group.counters[0].get_name(), "File cache entries");
    assert_eq!(group.counters[0].value, Value::U64(1));
    let rows = &group.tables[0].rows;
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_ne!(row[0], Value::Str("ZERO(2)".into()));
    }
    let r0 = &rows[0];
    assert_eq!(r0.len(), 5);
    assert_eq!(r0[0], Value::Str("TEST(1)".into()));
    assert_eq!(r0[1], Value::U64(2));
    assert_eq!(r0[2], Value::U64(3));
    assert_eq!(r0[3], Value::U64(20));
    assert_eq!(r0[4], Value::U64(30));
    let r1 = &rows[1];
    assert_eq!(r1.len(), 5);
    assert_eq!(r1[0], Value::Str("Total".into()));
    assert_eq!(r1[1], Value::U64(2));
    assert_eq!(r1[2], Value::U64(3));
    assert_eq!(r1[3], Value::U64(20));
    assert_eq!(r1[4], Value::U64(30));
}

#[test]
fn up_can_include_zero_rows_by_policy() {
    let env = FileStatsEnv::default();
    let w = up_w(true, false, false, 0);
    let s = collect(
        &env,
        &w,
        DynamicStatsPolicy {
            include_zeros: true,
        },
    );
    assert_eq!(s.sections.len(), 1);
    let group = &s.sections[0].groups[0];
    assert_eq!(group.tables.len(), 1);
    let rows = &group.tables[0].rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 5);
    assert_eq!(rows[0][0], Value::Str("TEST(1)".into()));
    for cell in &rows[0][1..] {
        assert_eq!(*cell, Value::U64(0));
    }
    assert_eq!(rows[1].len(), 5);
    assert_eq!(rows[1][0], Value::Str("Total".into()));
    for cell in &rows[1][1..] {
        assert_eq!(*cell, Value::U64(0));
    }
}
