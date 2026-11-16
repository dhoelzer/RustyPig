//! Replay of `tools/stx_harness/vectors.txt` (the 44-line ground-truth
//! transcript of ORIGINAL utils/stats/{output_text,utils}.cc @
//! fe29cbe7403a through the marker-witness probe) plus translations of
//! all 6 upstream `[stats_output_text]` TEST_CASEs from
//! `src/utils/stats/test/stats_output_text_test.cc` (the C++ `gate` runs
//! the suite verbatim: 37 assertions / 6 cases green).
use snort3::utils::stats::output_text::{
    MemoryReport, RenderEnv, StatsLogSink, calc_pct, counter_value_as_u64, render_text,
    value_as_text,
};
use snort3::utils::stats::response_buf::ControlConn;
use snort3::utils::stats::snapshot::{Builder, Snapshot, Value, counter_new};
use snort3::utils::stats::utils::{RenderOptions, is_zero, should_render};

/// Capturing sink mirroring BOTH the upstream gate witnesses (call
/// counters + last-message capture) and the probe's marker dump.
#[derive(Default)]
struct CapturingSink {
    log_text_calls: u32,
    log_count_calls: u32,
    log_stat_calls: u32,
    log_text_message: String,
    log_count_name: String,
    log_count_value: u64,
    lines: Vec<String>,
    set_conn_called: bool,
    set_conn_nulls: u32,
}

type MemPrints = Vec<(bool, bool)>;

impl StatsLogSink for CapturingSink {
    fn set_log_conn(&mut self, conn: Option<&mut dyn ControlConn>) {
        self.set_conn_called = true;
        if conn.is_none() {
            self.set_conn_nulls += 1;
        }
    }
    fn log_label(&mut self, s: &str) {
        self.lines.push(format!("<LL>{s}<LL_END>"));
    }
    fn log_text(&mut self, s: &str) {
        self.log_text_calls += 1;
        self.log_text_message = s.to_string();
        self.lines.push(format!("<LT>{s}<LT_END>"));
    }
    fn log_count(&mut self, name: &str, value: u64) {
        self.log_count_calls += 1;
        self.log_count_name = name.to_string();
        self.log_count_value = value;
        self.lines.push(format!("<LC>{name} {value}<LC_END>"));
    }
    fn log_stat(&mut self, name: &str, n: u64, tot: u64) {
        self.log_stat_calls += 1;
        self.lines.push(format!("<LC2>{name} {n}/{tot}<LC2_END>"));
    }
}

struct CapturingMem<'a>(&'a mut MemPrints);

impl MemoryReport for CapturingMem<'_> {
    fn print(&mut self, verbose: bool, initial: bool) {
        self.0.push((verbose, initial));
    }
}

/// Render one snapshot exactly as the probe driver does: log lines in
/// call order, then MC lines (MemoryCap witness prints fire AFTER the
/// section's own log output -- every pinned snapshot has one section
/// whose name may or may not trigger it), all appended to `out`.
/// Returns the sink so upstream-style checks can inspect it.
fn render_case(
    out: &mut Vec<String>,
    case: &str,
    snap: &Snapshot,
    opt: &RenderOptions,
) -> CapturingSink {
    out.push(format!("CASE {case}"));
    let mut sink = CapturingSink::default();
    let mut mem: MemPrints = Vec::new();
    {
        let mut cmem = CapturingMem(&mut mem);
        let mut env = RenderEnv {
            sink: &mut sink,
            memory: &mut cmem,
            log_verbose: false, // probe: SnortConfig::logging_flags == 0
        };
        // render_text entry passes the ControlConn* through: the probe
        // always passes nullptr, matching C's set_log_conn(nullptr)
        // (probe S1 pins set_conn_called=1 set_conn_nulls=2).
        render_text(&mut env, None, snap, opt);
    }
    for line in sink.lines.iter() {
        out.push(line.clone());
    }
    for (v, i) in mem {
        out.push(format!("<MC>verbose={} initial={}<MC_END>", v as i32, i as i32));
    }
    sink
}

// ======================================================== gate suite
#[test]
fn counter_values_convert_to_unsigned_values() {
    let mut c = counter_new();
    let mut conv = |v: Value| {
        c.value = v;
        counter_value_as_u64(&c)
    };
    assert_eq!(conv(Value::Mono), 0);
    assert_eq!(conv(Value::Bool(false)), 0);
    assert_eq!(conv(Value::Bool(true)), 0);
    assert_eq!(conv(Value::I64(-1)), 0);
    assert_eq!(conv(Value::I64(0)), 0);
    assert_eq!(conv(Value::I64(42)), 42);
    assert_eq!(conv(Value::U64(0)), 0);
    assert_eq!(conv(Value::U64(42)), 42);
    assert_eq!(conv(Value::F64(0.0)), 0);
    assert_eq!(conv(Value::F64(-1.25)), 0);
    assert_eq!(conv(Value::F64(42.75)), 42);
    assert_eq!(conv(Value::Str("42".into())), 0);
}

#[test]
fn values_render_as_text() {
    assert_eq!(value_as_text(&Value::Mono), "");
    assert_eq!(value_as_text(&Value::Bool(false)), "false");
    assert_eq!(value_as_text(&Value::Bool(true)), "true");
    assert_eq!(value_as_text(&Value::I64(-42)), "-42");
    assert_eq!(value_as_text(&Value::I64(42)), "42");
    assert_eq!(value_as_text(&Value::U64(42)), "42");
    assert_eq!(value_as_text(&Value::F64(1.25)), "1.250");
    assert_eq!(value_as_text(&Value::F64(0.0)), "0.000");
    assert_eq!(value_as_text(&Value::Str(String::new())), "");
    assert_eq!(value_as_text(&Value::Str("active".into())), "active");
}

#[test]
fn percentages_handle_zero_totals() {
    assert_eq!(calc_pct(0, 0), 0.0);
    assert_eq!(calc_pct(1, 0), 0.0);
    assert_eq!(calc_pct(1, 4), 25.0);
}

#[test]
fn output_skips_empty_tables_in_renderable_groups() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let grp = Builder::group(sec, "appid");
        // table with columns but NO rows -> not renderable, emits nothing
        Builder::table(grp, "empty", vec!["name".into()], false);
        let mut counter = counter_new();
        counter.set_name_static("packets");
        counter.value = Value::U64(1);
        grp.counters.push(counter);
    }
    let mut out = Vec::new();
    let sink = render_case(&mut out, "X", &snap, &RenderOptions::default());
    assert_eq!(sink.log_text_calls, 0);
    assert_eq!(sink.log_count_calls, 1);
    assert_eq!(sink.log_count_name, "packets");
    assert_eq!(sink.log_count_value, 1);
}

#[test]
fn output_renders_zero_count_counters_when_requested() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let grp = Builder::group(sec, "appid");
        let mut counter = counter_new();
        counter.set_name_static("packets");
        counter.value = Value::U64(0);
        grp.counters.push(counter);
    }
    let opt = RenderOptions { include_zeros: true };
    let mut out = Vec::new();
    let sink = render_case(&mut out, "X", &snap, &opt);
    assert_eq!(sink.log_count_calls, 0);
    assert_eq!(sink.log_stat_calls, 0);
    assert_eq!(sink.log_text_calls, 1);
    assert_eq!(sink.log_text_message, "                  packets: 0");
}

#[test]
fn output_renders_zero_percentage_counters_when_requested() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let grp = Builder::group(sec, "appid");
        let mut counter = counter_new();
        counter.set_name_static("packets");
        counter.value = Value::U64(0);
        counter.total = Some(10);
        grp.counters.push(counter);
    }
    let opt = RenderOptions { include_zeros: true };
    let mut out = Vec::new();
    let sink = render_case(&mut out, "X", &snap, &opt);
    assert_eq!(sink.log_count_calls, 0);
    assert_eq!(sink.log_stat_calls, 0);
    assert_eq!(sink.log_text_calls, 1);
    // exact: 20 pad + name + ": " + 0 left-padded to 12 + TAB +
    // "(  0.000%)" with pct right-padded to 7
    assert_eq!(
        sink.log_text_message,
        "                  packets: 0           \t(  0.000%)"
    );
}

/// utils.cc should_render semantics (the renderer's zero gate; no
/// upstream suite covers utils.cc itself -- probe S7 pins the group
/// skip, this pins the fn).
#[test]
fn should_render_semantics() {
    let mut c = counter_new();
    assert!(is_zero(&c)); // monostate
    for z in [
        Value::Bool(false),
        Value::I64(0),
        Value::U64(0),
        Value::F64(0.0),
        Value::Str(String::new()),
    ] {
        c.value = z;
        assert!(is_zero(&c));
    }
    for nz in [
        Value::Bool(true),
        Value::I64(-1),
        Value::U64(1),
        Value::F64(-0.5),
        Value::Str("x".into()),
    ] {
        c.value = nz;
        assert!(!is_zero(&c));
    }
    let off = RenderOptions::default();
    let on = RenderOptions { include_zeros: true };
    c.value = Value::U64(0);
    assert!(!should_render(&c, &off));
    assert!(should_render(&c, &on));
}

// =============================================== whole-transcript replay
#[test]
fn stx_transcript_replay() {
    let mut out: Vec<String> = Vec::new();

    // S1: Summary Statistics section triggers MemoryCap::print; empty
    // group (no counters, no tables) -> LogLabel(section) only.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            b.section("Summary Statistics");
        }
        let sink = render_case(&mut out, "S1", &snap, &RenderOptions::default());
        out.push(format!(
            "S1 set_conn_called={} set_conn_nulls={}",
            sink.set_conn_called as i32,
            sink.set_conn_nulls
        ));
    }

    // S2: zero counters (include_zeros) -> render_zero_counter: 25-wide
    // right-padded name, ": ", 12-wide left value, percent branch with
    // real tab, 7-wide right fixed 3dp pct.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("Module Statistics");
            let grp = Builder::group(sec, "appid");
            Builder::counter(grp, "packets", Value::U64(0));
            let mut c2 = counter_new();
            c2.set_name_static("drop%");
            c2.value = Value::U64(0);
            c2.total = Some(10);
            grp.counters.push(c2);
            let mut c3 = counter_new();
            c3.set_name_static("neg-int");
            c3.value = Value::I64(-5);
            grp.counters.push(c3);
            let mut c4 = counter_new();
            c4.set_name_static("-0 double");
            c4.value = Value::F64(-0.0);
            grp.counters.push(c4);
        }
        let opt = RenderOptions { include_zeros: true };
        render_case(&mut out, "S2", &snap, &opt);
    }

    // S3: >25-char counter names truncate (LC name byte-truncation);
    // non-zero counters LogStat/LogCount; zero (include_zeros=false)
    // invisible; percent-without-total ignored.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("Other");
            let grp = Builder::group(sec, "long");
            Builder::counter(
                grp,
                "name-that-is-definitely-over-twenty-five-chars",
                Value::U64(7),
            );
            Builder::counter(grp, "with-total", Value::U64(1));
            grp.counters.last_mut().unwrap().total = Some(4);
            Builder::counter(grp, "not-shown", Value::U64(0));
            let mut cp = counter_new();
            cp.set_name_static("pct-only");
            cp.value = Value::U64(2);
            cp.percent = Some(33.3);
            grp.counters.push(cp);
        }
        render_case(&mut out, "S3", &snap, &RenderOptions::default());
    }

    // S4: tables render before counters; header from columns; first-
    // column colon punct; per-row truncation; lone-value row; empty-
    // first-column table.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("T Sections");
            let grp = Builder::group(sec, "tables");
            let t1 = Builder::table(
                grp,
                "colon table",
                vec!["name".into(), "count".into(), "percent".into()],
                true,
            );
            Builder::row(
                t1,
                vec![Value::Str("row-one".into()), Value::U64(12), Value::F64(33.3)],
            );
            Builder::row(
                t1,
                vec![
                    Value::Str("x-that-is-over-twenty-five-chars-long".into()),
                    Value::Str("val".into()),
                    Value::Mono,
                ],
            );
            Builder::row(t1, vec![Value::Str("solo".into())]);
            let t2 = Builder::table(grp, "nocolon", vec!["".into(), "second".into()], false);
            Builder::row(t2, vec![Value::Str("a".into()), Value::Str("bb".into())]);
            Builder::counter(grp, "tail", Value::U64(9));
        }
        render_case(&mut out, "S4", &snap, &RenderOptions::default());
    }

    // S5: value_as_text variants via first column; monostate table cell
    // renders empty; monostate counter -> u64 0 plain "0".
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("V2");
            let grp = Builder::group(sec, "values");
            let t = Builder::table(grp, "types", vec!["v".into()], true);
            Builder::row(t, vec![Value::Bool(true)]);
            Builder::row(t, vec![Value::Bool(false)]);
            Builder::row(t, vec![Value::I64(-42)]);
            Builder::row(t, vec![Value::F64(1.25)]);
            Builder::row(t, vec![Value::F64(1e6)]);
            Builder::row(t, vec![Value::Mono]);
            Builder::row(t, vec![Value::Str("active".into())]);
            let mut cm = counter_new();
            cm.set_name_static("mono");
            cm.value = Value::Mono;
            grp.counters.push(cm);
        }
        let opt = RenderOptions { include_zeros: true };
        render_case(&mut out, "S5", &snap, &opt);
    }

    // S6: section name with trailing space does NOT match
    // SUMMARY_STATS_SECTION exactly -> no MemoryCap::print.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            b.section("Summary Statistics ");
        }
        render_case(&mut out, "S6", &snap, &RenderOptions::default());
    }

    // S7: group with only non-renderable content is skipped entirely;
    // section label still emitted; empty-row table not renderable.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("S7sec");
            let grp = Builder::group(sec, "skipme");
            Builder::counter(grp, "zeros", Value::U64(0));
            Builder::table(grp, "notable", vec!["c".into()], true);
        }
        render_case(&mut out, "S7", &snap, &RenderOptions::default());
    }

    out.push("DONE".to_string());

    let vectors = include_str!("../tools/stx_harness/vectors.txt");
    let want: Vec<&str> = vectors.lines().collect();
    assert_eq!(out.len(), want.len(), "line count mismatch");
    for (i, (g, e)) in out.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, e, "line {}", i + 1);
    }
}
