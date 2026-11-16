//! Replay of `tools/sjson_harness/vectors.txt` (the 22-line ground-truth
//! transcript of ORIGINAL utils/stats/output_json.cc +
//! helpers/json_stream.cc @ fe29cbe7403a through the dump probe) plus
//! translations of all 11 upstream `[stats_output_json]` TEST_CASEs
//! from `src/utils/stats/test/stats_output_json_test.cc` (the C++ gate
//! ALSO compiles two more suites verbatim: the 6 embedded
//! `[Json_Stream]` escape cases via -DUNIT_TEST and the `[json_stream]
//! basic` suite from helpers/test/json_stream_test.cc -- 73 assertions
//! / 18 cases green; those two are already mirrored by
//! tests/json_stream_test.rs against the existing Rust port).
use snort3::framework::counts::CountType;
use snort3::helpers::json_stream::{escape_json_append, JsonStream};
use snort3::utils::stats::output_json::render_json;
use snort3::utils::stats::snapshot::{Builder, Snapshot, Value, counter_new};
use snort3::utils::stats::utils::RenderOptions;

fn render(snap: &Snapshot, opt: &RenderOptions) -> String {
    let mut out: Vec<u8> = Vec::new();
    render_json(&mut out, snap, opt);
    String::from_utf8(out).unwrap()
}

// ==================================================== upstream suite
#[test]
fn json_renders_an_empty_snapshot() {
    let snap = Snapshot::default();
    let expected = "{ \"sections\": [  ] }\n";
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_skips_groups_without_renderable_content() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Packet Statistics");
        Builder::group(sec, "empty");
        let g2 = Builder::group(sec, "zero");
        Builder::counter(g2, "packets", Value::U64(0));
        let g3 = Builder::group(sec, "empty_table");
        Builder::table(g3, "flows", vec!["flow".into()], false);
    }
    let expected =
        "{ \"sections\": [ { \"name\": \"Packet Statistics\", \"groups\": [  ] } ] }\n";
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_filters_each_zero_value_type() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Packet Statistics");
        let g = Builder::group(sec, "values");
        Builder::counter(g, "unset", Value::Mono);
        Builder::counter(g, "false", Value::Bool(false));
        Builder::counter(g, "true", Value::Bool(true));
        Builder::counter(g, "signed_zero", Value::I64(0));
        Builder::counter(g, "signed", Value::I64(-5));
        Builder::counter(g, "unsigned_zero", Value::U64(0));
        Builder::counter(g, "unsigned", Value::U64(7));
        Builder::counter(g, "double_zero", Value::F64(0.0));
        Builder::counter(g, "double", Value::F64(1.25));
        Builder::counter(g, "empty_string", Value::Str(String::new()));
        Builder::counter(g, "string", Value::Str("active".into()));
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Packet Statistics\", \"groups\": [ { \"name\": \"values\", \"counters\": [ ",
        "{ \"name\": \"true\", \"value\": true }, ",
        "{ \"name\": \"signed\", \"value\": -5 }, ",
        "{ \"name\": \"unsigned\", \"value\": 7 }, ",
        "{ \"name\": \"double\", \"value\": 1.250 }, ",
        "{ \"name\": \"string\", \"value\": \"active\" } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_filters_zeros_and_trims_metadata() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Packet Statistics");
        let g = Builder::group(sec, "codec");
        let mut zero = counter_new();
        zero.set_name_static("total");
        zero.value = Value::U64(0);
        zero.peg_type = Some(CountType::Sum);
        g.counters.push(zero);
        let mut now = counter_new();
        now.set_name_static("current");
        now.value = Value::U64(7);
        now.peg_type = Some(CountType::Now);
        g.counters.push(now);
        let mut max = counter_new();
        max.set_name_static("peak");
        max.value = Value::U64(9);
        max.peg_type = Some(CountType::Max);
        g.counters.push(max);
        let mut percent = counter_new();
        percent.set_name_static("tcp\"name");
        percent.value = Value::U64(3);
        percent.total = Some(10);
        percent.percent = Some(30.0);
        g.counters.push(percent);
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Packet Statistics\", \"groups\": [ { \"name\": \"codec\", \"counters\": [ ",
        "{ \"name\": \"current\", \"value\": 7 }, ",
        "{ \"name\": \"peak\", \"value\": 9 }, ",
        "{ \"name\": \"tcp\\\"name\", \"value\": 3, \"percent\": 30.000 } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_renders_tables_with_mixed_value_types() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let g = Builder::group(sec, "appid");
        let t = Builder::table(
            g,
            "flows",
            vec!["name".into(), "enabled".into(), "delta".into(), "rate".into(), "state".into()],
            false,
        );
        Builder::row(
            t,
            vec![
                Value::Str("tcp\"name".into()),
                Value::Bool(true),
                Value::I64(-2),
                Value::F64(1.25),
                Value::Mono,
            ],
        );
        Builder::row(
            t,
            vec![
                Value::Str("udp\\name".into()),
                Value::Bool(false),
                Value::U64(42),
                Value::F64(0.5),
                Value::Str("done".into()),
            ],
        );
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Module Statistics\", \"groups\": [ { \"name\": \"appid\", ",
        "\"counters\": [  ], \"tables\": [ { \"name\": \"flows\", \"columns\": [ ",
        "\"name\", \"enabled\", \"delta\", \"rate\", \"state\" ], \"rows\": [ ",
        "[ \"tcp\\\"name\", true, -2, 1.250, null ], ",
        "[ \"udp\\\\name\", false, 42, 0.500, \"done\" ] ] } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_renders_a_single_column_table() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let g = Builder::group(sec, "appid");
        let t = Builder::table(g, "flows", vec!["name".into()], false);
        Builder::row(t, vec![Value::Str("tcp".into())]);
        Builder::row(t, vec![Value::Str("udp".into())]);
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Module Statistics\", \"groups\": [ { \"name\": \"appid\", ",
        "\"counters\": [  ], \"tables\": [ { \"name\": \"flows\", \"columns\": [ ",
        "\"name\" ], \"rows\": [ [ \"tcp\" ], [ \"udp\" ] ] } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_skips_empty_tables_among_renderable_tables() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let g = Builder::group(sec, "dynamic");
        let cols = vec!["name".into(), "count".into()];
        Builder::table(g, "empty", cols.clone(), false);
        let t = Builder::table(g, "active", cols, false);
        Builder::row(t, vec![Value::Str("row".into()), Value::U64(1)]);
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Module Statistics\", \"groups\": [ { \"name\": \"dynamic\", ",
        "\"counters\": [  ], \"tables\": [ { \"name\": \"active\", \"columns\": [ ",
        "\"name\", \"count\" ], \"rows\": [ [ \"row\", 1 ] ] } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_builder_appends_dynamic_table_data() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Appid Statistics");
        let g = Builder::group(sec, "detected apps and services");
        let t = Builder::table(
            g,
            "detected apps and services",
            vec!["Application".into(), "Services".into(), "Clients".into()],
            true,
        );
        Builder::row(t, vec![Value::Str("http/2".into()), Value::U64(1), Value::U64(0)]);
        Builder::counter(g, "dynamic_rows", Value::U64(1));
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Appid Statistics\", \"groups\": [ { \"name\": \"detected apps and services\", ",
        "\"counters\": [ { \"name\": \"dynamic_rows\", \"value\": 1 } ], ",
        "\"tables\": [ { \"name\": \"detected apps and services\", \"columns\": [ ",
        "\"Application\", \"Services\", \"Clients\" ], \"rows\": [ [ \"http/2\", 1, 0 ] ] } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_builder_owns_dynamic_counter_names() {
    // C Builder::counter(group, const char*, ...) copies the C string
    // into the counter's owned std::string, so mutating the source
    // std::string afterwards is invisible to the snapshot. The Rust
    // port borrows an immutable &str, so the equivalent C "mutated
    // name" CHECK holds trivially.
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Appid Statistics");
        let g = Builder::group(sec, "dynamic counters");
        let counter_name = String::from("temporary name");
        Builder::counter(g, counter_name.as_str(), Value::U64(1));
        let counter_name = String::from("mutated name");
        assert_eq!(counter_name, "mutated name");
    }
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Appid Statistics\", \"groups\": [ { \"name\": \"dynamic counters\", ",
        "\"counters\": [ { \"name\": \"temporary name\", \"value\": 1 } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &RenderOptions::default()), expected);
}

#[test]
fn json_preserves_rendered_empty_strings() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let g = Builder::group(sec, "appid");
        Builder::counter(g, "empty_string", Value::Str(String::new()));
        let t = Builder::table(
            g,
            "flows",
            vec!["name".into(), "state".into(), "note".into()],
            false,
        );
        Builder::row(
            t,
            vec![
                Value::Str("tcp".into()),
                Value::Str(String::new()),
                Value::Str("done".into()),
            ],
        );
    }
    let opt = RenderOptions { include_zeros: true };
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Module Statistics\", \"groups\": [ { \"name\": \"appid\", \"counters\": [ ",
        "{ \"name\": \"empty_string\", \"value\": \"\" } ], \"tables\": [ { \"name\": \"flows\", \"columns\": [ ",
        "\"name\", \"state\", \"note\" ], \"rows\": [ [ \"tcp\", \"\", \"done\" ] ] } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &opt), expected);
}

#[test]
fn json_can_include_zeros_by_policy() {
    let mut snap = Snapshot::default();
    {
        let mut b = Builder::new(&mut snap);
        let sec = b.section("Module Statistics");
        let g = Builder::group(sec, "appid");
        let mut counter = counter_new();
        counter.set_name_static("packets");
        counter.value = Value::U64(0);
        counter.peg_type = Some(CountType::Sum);
        g.counters.push(counter);
    }
    let opt = RenderOptions { include_zeros: true };
    let expected = concat!(
        "{ \"sections\": [ { \"name\": \"Module Statistics\", \"groups\": [ { \"name\": \"appid\", \"counters\": [ ",
        "{ \"name\": \"packets\", \"value\": 0 } ] } ] } ] }\n",
    );
    assert_eq!(render(&snap, &opt), expected);
}

// =============================================== whole-transcript replay

/// Mirror of the C probe `dump()`: runs a JsonStream/render body into a
/// byte buffer and prints the same marker line (len pins the
/// level-0 std::endl).
fn js_dump<F>(tag: &str, f: F) -> String
where
    F: FnOnce(&mut dyn std::io::Write),
{
    let mut buf: Vec<u8> = Vec::new();
    f(&mut buf);
    let s = String::from_utf8(buf).unwrap();
    format!("<J>{tag}<LN>{}<JJ>{s}<JE>", s.len())
}

#[test]
fn sjson_transcript_replay() {
    let mut got: Vec<String> = Vec::new();

    // J1: empty snapshot
    {
        let snap = Snapshot::default();
        got.push(js_dump("J1", |w| render_json(w, &snap, &RenderOptions::default())));
    }

    // J2: put_value value branches + percent key; zero (default options)
    // filtered; monostate counter -> null (is_zero filters Mono by
    // DEFAULT? no: it IS filtered -- counter_new() MONO value is zero,
    // so with default options `mono` never renders; the vector proves
    // it, hence the C probe pins the counter exists but invisible).
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("Summary Statistics");
            let g = Builder::group(sec, "g2");
            Builder::counter(g, "zero", Value::U64(0));
            Builder::counter(g, "neg", Value::I64(-5));
            Builder::counter(g, "flag", Value::Bool(true));
            Builder::counter(g, "f", Value::F64(0.25));
            Builder::counter(g, "pc", Value::Str("strval".into()));
            let mut c = counter_new();
            c.set_name_static("pct");
            c.value = Value::U64(2);
            c.percent = Some(33.3);
            g.counters.push(c);
            let mut c2 = counter_new();
            c2.set_name_static("mono");
            g.counters.push(c2);
        }
        got.push(js_dump("J2", |w| render_json(w, &snap, &RenderOptions::default())));
    }

    // J3: tables array opens despite a row-less table (rendered as no
    // table entry but array NOT omitted), mixed row widths, monostate
    // cell null.
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("S3");
            let g = Builder::group(sec, "g3");
            Builder::counter(g, "live", Value::U64(1));
            let t = Builder::table(g, "t", vec!["name".into(), "v".into()], false);
            Builder::row(t, vec![Value::Str("row-one".into()), Value::U64(12)]);
            Builder::row(
                t,
                vec![
                    Value::Str("x-that-is-over-twenty-five-chars-long".into()),
                    Value::Str("val".into()),
                    Value::Mono,
                ],
            );
            Builder::row(t, vec![Value::Str("solo".into())]);
            Builder::table(g, "empty", vec!["c".into()], false);
        }
        got.push(js_dump("J3", |w| render_json(w, &snap, &RenderOptions::default())));
    }

    // J4: include_zeros makes an all-zero group renderable
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("S4");
            let g = Builder::group(sec, "z");
            Builder::counter(g, "zero", Value::U64(0));
        }
        let opt = RenderOptions { include_zeros: true };
        got.push(js_dump("J4", |w| render_json(w, &snap, &opt)));
    }

    // J5: empty-string counter under DEFAULT options: is_zero("") ->
    // filtered, so the group has nothing renderable -> section with
    // empty groups
    {
        let mut snap = Snapshot::default();
        {
            let mut b = Builder::new(&mut snap);
            let sec = b.section("S5");
            let g = Builder::group(sec, "g5");
            Builder::counter(g, "empty", Value::Str(String::new()));
        }
        got.push(js_dump("J5", |w| render_json(w, &snap, &RenderOptions::default())));

        // J5b: put(key, std::string) empty early-return consumes
        // NEITHER separator NOR key
        got.push(js_dump("J5b", |w| {
            let mut s = JsonStream::new(w);
            s.open(None);
            s.put_string_q(Some("gone"), "");
            s.put_string_q(Some("still"), "here");
            s.close();
        }));

        // J5c: null char* -> null (split consumed); empty char* ->
        // fully silent; bools
        got.push(js_dump("J5c", |w| {
            let mut s = JsonStream::new(w);
            s.open(None);
            s.put_cstr(Some("nullptr"), None);
            s.put_cstr(Some("nempty"), Some(""));
            s.put_true(Some("t"));
            s.put_false(Some("f"));
            s.close();
        }));
    }

    // J6: escapes through the stream. C probe inputs are raw BYTES,
    // including 0x01-0x03 and 0x80 (not valid UTF-8): feed the
    // byte-level entry to reproduce byte-exactly.
    got.push(js_dump("J6", |w| {
        let mut s = JsonStream::new(w);
        s.open(None);
        s.put_string_bytes(Some("specials"), b"\" \\ \x08 \x0c \n \r \t");
        s.put_string_bytes(Some("ctrl"), b"\x01\x02\x03");
        s.put_string_bytes(Some("del"), b"\x7e\x7f\x80");
        s.close();
    }));

    // J7: level/separators: inner closes inside an array do NOT endl;
    // only the level-0 root close does
    got.push(js_dump("J7", |w| {
        let mut s = JsonStream::new(w);
        s.open(None);
        s.open_array(Some("a"));
        s.open(None);
        s.uput_u64(Some("n"), 1);
        s.close();
        s.open(None);
        s.put_i64(Some("m"), -2);
        s.close();
        s.close_array();
        s.close();
    }));

    // J8: precision per-put (0.1, 0.125, 0.12 -- each put sets its own
    // precision before writing); ints/strings unaffected
    got.push(js_dump("J8", |w| {
        let mut s = JsonStream::new(w);
        s.open(None);
        s.put_f64(Some("p1"), 0.125, 1);
        s.put_f64(Some("p3"), 0.125, 3);
        s.put_f64(Some("p2"), 0.125, 2);
        s.put_i64(Some("i"), 7);
        s.put_string_q(Some("str"), "0.125");
        s.close();
    }));

    // <E>: escape_json_append direct-call sequence (probe J9)
    {
        let mut out = String::new();
        escape_json_append(&mut out, b"a<b>c"); // no escapes: pos == len
        out.push('|');
        escape_json_append(&mut out, b"\"q"); // pos == 0: no pre-append
        out.push('|');
        escape_json_append(&mut out, b"pre\tpost"); // pos == 3: pre-append
        out.push('|');
        escape_json_append(&mut out, b""); // empty: early return, no push
        got.push(format!("<E>{out}<EE>"));
    }

    got.push("DONE".to_string());

    // the pinned <LN> length makes each dumped record span TWO physical
    // lines in vectors.txt (the level-0 std::endl is inside the dump),
    // so join my records + separators and compare as one transcript.
    let mine = got.join("\n") + "\n";
    let vectors = include_str!("../tools/sjson_harness/vectors.txt");
    assert_eq!(mine, vectors);
}
