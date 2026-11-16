//! Faithful Rust port of `utils/stats/output_json.{h,cc}` (ground truth
//! @ fe29cbe7403a): the JSON renderer for the stats snapshot layer.
//!
//! Fidelity notes / deviations (see KNOWN DEVIATIONS.md):
//! - C free functions are file-statics except `render_json`; the Rust
//!   helpers are `pub` so the parity test exercises the same function
//!   granularity the upstream suite drives through `render_json`.
//! - `Value` variant dispatch (`std::get_if` chain) becomes a match on
//!   the snapshot `Value` enum; the trailing C `else json.put(key)`
//!   arm is unreachable given the exhaustive variant list but kept
//!   (Rust `_ =>` with the same put_null behavior).
//! - `JsonStream` (already ported in `helpers/json_stream.rs`) over a
//!   `std::io::Write` sink replaces `std::ostream&`.
use std::io::Write;

use crate::helpers::json_stream::JsonStream;
use crate::utils::stats::snapshot::{Counter, Group, Section, Snapshot, Table, Value};
use crate::utils::stats::utils::{should_render, RenderOptions};

/// C static put_value(JsonStream&, const char* key, const Value&).
pub fn put_value(json: &mut JsonStream, key: Option<&str>, value: &Value) {
    match value {
        // json.put(key);
        Value::Mono => json.put_null(key),
        Value::Bool(v) => {
            if *v {
                json.put_true(key);
            } else {
                json.put_false(key);
            }
        }
        Value::I64(v) => json.put_i64(key, *v),
        Value::U64(v) => json.uput_u64(key, *v),
        Value::F64(v) => json.put_f64(key, *v, 3),
        // json.put_string(key, *v): NOTE the string branch routes to
        // put_string (always writes, even empty ""), NOT the
        // early-returning put(key, const std::string&) overload.
        Value::Str(v) => json.put_string(key, v),
    }
}

/// C static has_renderable_rows(const Table&, const RenderOptions&).
/// The options parameter is unused in C; kept positionally.
#[allow(clippy::unused_unit)]
pub fn has_renderable_rows(table: &Table, _options: &RenderOptions) -> bool {
    !table.rows.is_empty()
}

/// C static has_renderable_content(const Group&, const RenderOptions&):
/// counters checked BEFORE tables.
pub fn has_renderable_content(group: &Group, options: &RenderOptions) -> bool {
    for counter in &group.counters {
        if should_render(counter, options) {
            return true;
        }
    }

    for table in &group.tables {
        if has_renderable_rows(table, options) {
            return true;
        }
    }

    false
}

/// C static render_counter(JsonStream&, const Counter&).
pub fn render_counter(json: &mut JsonStream, counter: &Counter) {
    json.open(None);
    // C get_name() returns const char* -> the char* overload: a name
    // with an embedded NUL truncates at the NUL (strlen semantics).
    json.put_cstr(Some("name"), Some(counter.get_name()));
    put_value(json, Some("value"), &counter.value);

    if let Some(pct) = counter.percent {
        // NOTE: unlike the TEXT renderer (which ignores percent), the
        // JSON renderer emits a "percent" key whenever set.
        json.put_f64(Some("percent"), pct, 3);
    }

    json.close();
}

/// C static render_table(JsonStream&, const Table&).
pub fn render_table(json: &mut JsonStream, table: &Table) {
    json.open(None);
    json.put_cstr(Some("name"), Some(&table.name));

    json.open_array(Some("columns"));
    for column in &table.columns {
        // C json.put(nullptr, column) -> put(key=nullptr,
        // const std::string&): the empty-early-return overload (an
        // empty column writes NOTHING, not even a separator).
        json.put_string_q(None, column);
    }
    json.close_array();

    json.open_array(Some("rows"));
    for row in &table.rows {
        json.open_array(None);
        for cell in row {
            put_value(json, None, cell);
        }
        json.close_array();
    }
    json.close_array();

    json.close();
}

/// C static render_group(JsonStream&, const Group&, const
/// RenderOptions&): the "counters" array ALWAYS opens, the "tables"
/// array opens only when the group HAS tables — even if every table is
/// row-less and gets filtered inside, leaving `"tables": [  ]`.
pub fn render_group(json: &mut JsonStream, group: &Group, options: &RenderOptions) {
    json.open(None);
    json.put_string_q(Some("name"), &group.name);

    json.open_array(Some("counters"));
    for counter in &group.counters {
        if should_render(counter, options) {
            render_counter(json, counter);
        }
    }
    json.close_array();

    if !group.tables.is_empty() {
        json.open_array(Some("tables"));
        for table in &group.tables {
            if has_renderable_rows(table, options) {
                render_table(json, table);
            }
        }
        json.close_array();
    }

    json.close();
}

/// C static render_section(JsonStream&, const Section&, const
/// RenderOptions&).
pub fn render_section(json: &mut JsonStream, section: &Section, options: &RenderOptions) {
    json.open(None);
    json.put_cstr(Some("name"), Some(&section.name));

    json.open_array(Some("groups"));
    for group in &section.groups {
        if has_renderable_content(group, options) {
            render_group(json, group, options);
        }
    }
    json.close_array();

    json.close();
}

/// C void snort::stats::render_json(std::ostream& out, const Snapshot&,
/// const RenderOptions& = {}): the ONLY exported entry, and no
/// MemoryCap/logging side effects at all here (unlike render_text).
pub fn render_json(out: &mut dyn Write, snapshot: &Snapshot, options: &RenderOptions) {
    let mut json = JsonStream::new(out);

    json.open(None);
    json.open_array(Some("sections"));
    for section in &snapshot.sections {
        render_section(&mut json, section, options);
    }
    json.close_array();
    json.close();
}
