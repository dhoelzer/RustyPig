//! Faithful Rust port of `utils/stats/output_text.{h,cc}` (ground truth
//! @ fe29cbe7403a): the text renderer over a [`Snapshot`].
//!
//! The C++ layout manipulators (`std::setw`/`std::right`/`std::left` are
//! STREAM STATE — `setw` applies to the next insert only, the alignment
//! sticks) plus the `line.flags(flags)` save/restore around the row loop
//! are reproduced with explicit per-insert width/alignment format
//! strings: the observable strings are identical (verified byte-for-byte
//! against the locked 44-line transcript). The upstream `append_table_line`
//! reuses ONE `std::ostringstream` across header+rows with `line.str()
//! /clear()` between rows; since every insert sets its own width and the
//! flags are restored at function end, per-call Strings are
//! observationally identical (deviation: state, not bytes).
//!
//! Deviations for the externals this TU calls into (documented in
//! KNOWN DEVIATIONS.md):
//! - `LogLabel/LogText/LogCount/LogStat/set_log_conn` are the
//!   [`StatsLogSink`] trait seam. The real `log_stats.cc` formatting was
//!   ported/pinned separately (`log::log_stats`, row 17); `LogStat`
//!   itself is NOT yet ported there, and `set_log_conn`'s C THREAD_LOCAL
//!   `s_ctrlcon` routes `LogfRespond` inside those functions — both live
//!   on the sink side of the seam. The port calls `set_log_conn` exactly
//!   at C's two sites in `render_text` (order/count pinned by the probe).
//! - `memory::MemoryCap::print(verbose, initial=false)` is the
//!   [`MemoryReport`] seam (the print half of memory_cap.cc drags the
//!   heap-interface layer; later row). Called when the section name
//!   EQUALS "Summary Statistics" — byte-compare, pinned by S6 ("Summary
//!   Statistics " with trailing space does NOT match).
//! - `SnortConfig::log_verbose()` (static, `logging_flags &
//!   LOGGING_FLAG__VERBOSE`) becomes the `log_verbose` field on
//!   [`RenderEnv`]; the Rust `messages::LogEngine` carries `logging_flags`
//!   but the VERBOSE bit has no ported getter yet.
use super::snapshot::{Counter, Group, Section, Snapshot, Table, Value};
use super::utils::{RenderOptions, should_render};
use crate::utils::stats::response_buf::ControlConn;

const SUMMARY_STATS_SECTION: &str = "Summary Statistics";

// Text output column width; other renderers can choose their own layout.
const FIRST_COLUMN_WIDTH: usize = 25;
const COUNTER_VALUE_WIDTH: usize = 12;
const PERCENT_VALUE_WIDTH: usize = 7;
const PERCENT_PRECISION: usize = 3;

/// Seam for the `log_stats.cc` functions this TU calls (see module
/// header). `set_log_conn` mirrors C's set_log_conn at the render_text
/// entry/exit; the sink owns the C THREAD_LOCAL state.
pub trait StatsLogSink {
    fn set_log_conn(&mut self, conn: Option<&mut dyn ControlConn>);
    fn log_label(&mut self, s: &str);
    fn log_text(&mut self, s: &str);
    fn log_count(&mut self, name: &str, value: u64);
    fn log_stat(&mut self, name: &str, n: u64, tot: u64);
}

/// Seam for `memory::MemoryCap::print`.
pub trait MemoryReport {
    fn print(&mut self, verbose: bool, initial: bool);
}

/// Stands for the statics the C render path reads:
/// `SnortConfig::log_verbose()` at the MemoryCap call site.
pub struct RenderEnv<'a> {
    pub sink: &'a mut dyn StatsLogSink,
    pub memory: &'a mut dyn MemoryReport,
    pub log_verbose: bool,
}

/// static uint64_t counter_value_as_u64(const Counter& counter)
/// C ternary arms (`*v > 0 ? cast : 0`) kept as explicit if/else inside arms
/// rather than match guards, mirroring the C line-by-line.
#[allow(clippy::if_same_then_else, clippy::collapsible_match)]
pub fn counter_value_as_u64(counter: &Counter) -> u64 {
    match &counter.value {
        Value::U64(v) => *v,
        Value::I64(v) => {
            if *v > 0 {
                *v as u64
            } else {
                0
            }
        }
        Value::F64(v) => {
            if *v > 0.0 {
                *v as u64
            } else {
                0
            }
        }
        // monostate/bool/string arms (and the C fallthrough) -> 0
        _ => 0,
    }
}

/// static std::string value_as_text(const Value& value)
///
/// C++ `ostringstream << std::fixed << std::setprecision(3)` for doubles;
/// Rust `{:.3}` (round-half-to-even matches glibc on the pinned values).
/// infinity/NaN spellings can differ ("inf"/"nan" vs "inf"/"NaN") — no
/// pinned vector exercises them (deviation logged).
pub fn value_as_text(value: &Value) -> String {
    match value {
        Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::I64(v) => v.to_string(),
        Value::U64(v) => v.to_string(),
        Value::F64(v) => format!("{:.1$}", v, PERCENT_PRECISION),
        Value::Str(v) => v.clone(),
        // monostate: return {}; string arm already handled
        Value::Mono => String::new(),
    }
}

/// static std::string first_column_text(const Value& value)
fn first_column_text(value: &Value) -> String {
    let mut text = value_as_text(value);
    // C text.resize(25) truncates at BYTE count; Rust truncate matches.
    if text.len() > FIRST_COLUMN_WIDTH {
        text.truncate(FIRST_COLUMN_WIDTH);
    }
    text
}

/// static void append_table_line(std::ostringstream& line, ...)
/// Rust returns the completed line (state deviation noted up top).
fn append_table_line(values: &[Value], first_column_has_colon: bool) -> String {
    // const std::string first = values.empty() ? std::string() : first_column_text(values[0]);
    let first = match values.first() {
        Some(v) => first_column_text(v),
        None => String::new(),
    };
    let mut line = String::new();
    // line << std::setw(25) << std::right << first << (colon? ": " : " ");
    line.push_str(&format!("{:>1$}", first, FIRST_COLUMN_WIDTH));
    line.push_str(if first_column_has_colon { ": " } else { " " });

    // C indexes values[i] in the loop body (the separator test reads
    // the same i), so the indexed form is kept rather than iter().
    #[allow(clippy::needless_range_loop)]
    for i in 1..values.len() {
        if i > 1 {
            line.push(' ');
        }
        // line << std::setw(10) << std::left << value_as_text(values[i]);
        line.push_str(&format!("{:<10}", value_as_text(&values[i])));
    }
    // line.flags(flags); -- restore: every insert above set its own
    // width/alignment explicitly, so nothing stateful survives.
    line
}

/// static bool has_renderable_rows(const Table& table)
fn has_renderable_rows(table: &Table) -> bool {
    !table.rows.is_empty()
}

/// static bool has_renderable_content(const Group&, const RenderOptions&)
fn has_renderable_content(group: &Group, options: &RenderOptions) -> bool {
    for table in &group.tables {
        if has_renderable_rows(table) {
            return true;
        }
    }
    for counter in &group.counters {
        if should_render(counter, options) {
            return true;
        }
    }
    false
}

/// static void render_table(const Table&)
fn render_table(sink: &mut dyn StatsLogSink, table: &Table) {
    if !has_renderable_rows(table) {
        return;
    }

    let mut header: Vec<Value> = Vec::with_capacity(table.columns.len());
    for column in &table.columns {
        header.push(Value::Str(column.clone()));
    }
    sink.log_text(&append_table_line(&header, table.first_column_has_colon));

    for row in &table.rows {
        sink.log_text(&append_table_line(row, table.first_column_has_colon));
    }
}

/// static std::string counter_name_as_text(const Counter&)
fn counter_name_as_text(counter: &Counter) -> String {
    let mut text = counter.get_name().to_string();
    if text.len() > FIRST_COLUMN_WIDTH {
        text.truncate(FIRST_COLUMN_WIDTH);
    }
    text
}

/// static double calc_pct(uint64_t count, uint64_t total)
pub fn calc_pct(count: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    count as f64 / total as f64 * 100.0
}

/// static void render_zero_counter(const Counter&, uint64_t value)
fn render_zero_counter(sink: &mut dyn StatsLogSink, counter: &Counter, value: u64) {
    // line << setw(25) << right << name << ": ";
    let mut line = format!("{:>1$}", counter_name_as_text(counter), FIRST_COLUMN_WIDTH);
    line.push_str(": ");

    match counter.total {
        Some(total) => {
            // setw(12) left value << "\t(" << setw(7) right fixed
            // setprecision(3) pct << "%)"
            line.push_str(&format!("{:<1$}", value, COUNTER_VALUE_WIDTH));
            line.push_str("\t(");
            line.push_str(&format!(
                "{:>1$.2$}",
                calc_pct(value, total),
                PERCENT_VALUE_WIDTH,
                PERCENT_PRECISION
            ));
            line.push_str("%)");
        }
        None => line.push_str(&value.to_string()),
    }

    sink.log_text(&line);
}

/// static void render_counter(const Counter&, const RenderOptions&)
fn render_counter(sink: &mut dyn StatsLogSink, counter: &Counter, options: &RenderOptions) {
    let value = counter_value_as_u64(counter);

    if value != 0 || !options.include_zeros {
        // counter.percent is NOT consulted by the text renderer (only
        // total decides), pinned by S3's pct-only counter.
        match counter.total {
            Some(total) => sink.log_stat(counter.get_name(), value, total),
            None => sink.log_count(counter.get_name(), value),
        }
        return;
    }

    render_zero_counter(sink, counter, value);
}

/// static void render_group(const Group&, const RenderOptions&)
fn render_group(sink: &mut dyn StatsLogSink, group: &Group, options: &RenderOptions) {
    if !has_renderable_content(group, options) {
        return;
    }

    sink.log_label(&group.name);

    for table in &group.tables {
        render_table(sink, table);
    }

    for counter in &group.counters {
        if !should_render(counter, options) {
            continue;
        }

        render_counter(sink, counter, options);
    }
}

/// static void render_section(const Section&, const RenderOptions&)
fn render_section(sink: &mut dyn StatsLogSink, section: &Section, options: &RenderOptions) {
    sink.log_label(&section.name);

    for group in &section.groups {
        render_group(sink, group, options);
    }
}

/// void snort::stats::render_text(ControlConn*, const Snapshot&, const
/// RenderOptions&)
pub fn render_text(
    env: &mut RenderEnv<'_>,
    ctrlcon: Option<&mut dyn ControlConn>,
    snapshot: &Snapshot,
    options: &RenderOptions,
) {
    env.sink.set_log_conn(ctrlcon);

    for section in &snapshot.sections {
        render_section(env.sink, section, options);

        if section.name == SUMMARY_STATS_SECTION {
            env.memory.print(env.log_verbose, false); // initial_report default
        }
    }

    // C: set_log_conn(nullptr) -- second call site, pinned count in S1.
    env.sink.set_log_conn(None);
}
