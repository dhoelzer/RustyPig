//! Port of helpers/test/json_stream_test.cc (TEST_CASE "basic", 40+
//! SECTIONs) and the UNIT_TEST escape TEST_CASEs embedded in
//! helpers/json_stream.cc. Each SECTION is one #[test]: the C test shares
//! one ostringstream but every CHECK(ss.str() == ...) follows the section
//! body, and Catch re-runs the TEST_CASE body fresh per SECTION.

use snort3::helpers::json_stream::*;

// ---- the json_stream.cc embedded escape tests (check_escaping) ----
// C: oss.str(); put(field, std::string(input, i_len)); CHECK equals.
fn check_escaping(field: &str, input: &[u8], expected: &str) {
    let mut ss: Vec<u8> = Vec::new();
    {
        let mut js = JsonStream::new(&mut ss);
        js.put_string_q(Some(field), std::str::from_utf8(input).unwrap_or(""));
    }
    assert_eq!(String::from_utf8(ss).unwrap(), expected);
}

#[test]
fn escape_special_chars() {
    let field = "Special characters";
    let value = b"\" \\ \x08 \x0c \n \r \t";
    let expected = "\"Special characters\": \"\\\" \\\\ \\b \\f \\n \\r \\t\"";
    check_escaping(field, value, expected);
}

#[test]
fn escape_non_printable_chars() {
    let field = "Non printable";
    let value = b"\x01\x02\x03";
    let expected = "\"Non printable\": \"\\u0001\\u0002\\u0003\"";
    check_escaping(field, value, expected);
}

#[test]
fn escape_printable_chars() {
    let field = "Printable characters";
    let value = b"ABC abc 123";
    let expected = "\"Printable characters\": \"ABC abc 123\"";
    check_escaping(field, value, expected);
}

#[test]
fn escape_mixed_chars() {
    let field = "Mixed";
    let value = b"ABC \x01 \" \\ \x08 \x0c \n \r \t 123";
    let expected = "\"Mixed\": \"ABC \\u0001 \\\" \\\\ \\b \\f \\n \\r \\t 123\"";
    check_escaping(field, value, expected);
}

#[test]
fn escape_empty_string() {
    let field = "Empty string";
    let value = b"";
    let expected = "";
    check_escaping(field, value, expected);
}

#[test]
fn escape_no_escaping() {
    let field = "Normal string";
    let value = b"foobar";
    let expected = "\"Normal string\": \"foobar\"";
    check_escaping(field, value, expected);
}

// ---- json_stream_test.cc TEST_CASE("basic") ----

struct Js(Vec<u8>);
impl Js {
    fn stream(&mut self) -> JsonStream<'_> {
        JsonStream::new(&mut self.0)
    }
    fn s(&self) -> String {
        String::from_utf8(self.0.clone()).unwrap()
    }
}

fn out_check(js: &Js, expected: &str) {
    assert_eq!(js.s(), expected);
}

#[test]
fn empty_body() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.close();
    }
    out_check(&js, "{  }\n");
}

#[test]
fn empty_root_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open_array(None);
        st.close_array();
    }
    out_check(&js, "[  ]\n");
}

#[test]
fn empty_object() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open(Some("o"));
        st.close();
        st.close();
    }
    out_check(&js, "{ \"o\": {  } }\n");
}

#[test]
fn empty_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("a"));
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"a\": [  ] }\n");
}

#[test]
fn null() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_null(Some("n"));
    }
    out_check(&js, "\"n\": null");
}

#[test]
fn bool_true() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_true(Some("b"));
    }
    out_check(&js, "\"b\": true");
}

#[test]
fn bool_false() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_false(Some("b"));
    }
    out_check(&js, "\"b\": false");
}

#[test]
fn int() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_i64(Some("i"), 0);
    }
    out_check(&js, "\"i\": 0");
}

#[test]
fn real() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_f64(Some("r"), 2.5, 2);
    }
    out_check(&js, "\"r\": 2.50");
}

#[test]
fn string() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(Some("s"), Some("yo"));
    }
    out_check(&js, "\"s\": \"yo\"");
}

#[test]
fn empty_string_std() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_string_q(Some("s"), "");
    }
    out_check(&js, "");
}

#[test]
fn empty_cstring() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(Some("s"), Some(""));
    }
    out_check(&js, "");
}

#[test]
fn explicit_empty_string() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_string(Some("s"), "");
    }
    out_check(&js, "\"s\": \"\"");
}

#[test]
fn null_item() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_null(None);
    }
    out_check(&js, "null");
}

#[test]
fn bool_true_item() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_true(None);
    }
    out_check(&js, "true");
}

#[test]
fn bool_false_item() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_false(None);
    }
    out_check(&js, "false");
}

#[test]
fn int_item() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_i64(None, 1);
    }
    out_check(&js, "1");
}

#[test]
fn real_item() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_f64(None, 2.5, 2);
    }
    out_check(&js, "2.50");
}

#[test]
fn string_item() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(None, Some("it"));
    }
    out_check(&js, "\"it\"");
}

#[test]
fn backslash() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(None, Some("content:\\test\\;"));
    }
    out_check(&js, "\"content:\\\\test\\\\;\"");
}

#[test]
fn embedded_quotes() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(None, Some("content:\"foo\";"));
    }
    out_check(&js, "\"content:\\\"foo\\\";\"");
}

#[test]
fn special_characters() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(
            None,
            Some("content: / \" \\ $ # ! @ % ^ & * ' \u{8}\u{c}\t\r\n . "),
        );
    }
    out_check(
        &js,
        "\"content: / \\\" \\\\ $ # ! @ % ^ & * ' \\b\\f\\t\\r\\n . \"",
    );
}

#[test]
fn null_list() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_null(Some("i"));
        st.put_null(Some("j"));
    }
    out_check(&js, "\"i\": null, \"j\": null");
}

#[test]
fn bool_list() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_true(Some("i"));
        st.put_false(Some("j"));
    }
    out_check(&js, "\"i\": true, \"j\": false");
}

#[test]
fn int_list() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_i64(Some("i"), 2);
        st.put_i64(Some("j"), 3);
    }
    out_check(&js, "\"i\": 2, \"j\": 3");
}

#[test]
fn string_list() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.put_cstr(Some("s"), Some("alpha"));
        st.put_cstr(Some("t"), Some("beta"));
        st.put_cstr(Some("u"), Some("gamma"));
    }
    out_check(&js, "\"s\": \"alpha\", \"t\": \"beta\", \"u\": \"gamma\"");
}

#[test]
fn array_list() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("m"));
        st.close_array();
        st.open_array(Some("n"));
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"m\": [  ], \"n\": [  ] }\n");
}

#[test]
fn null_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("n"));
        st.put_null(None);
        st.put_null(None);
        st.put_null(None);
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"n\": [ null, null, null ] }\n");
}

#[test]
fn bool_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("b"));
        st.put_true(None);
        st.put_false(None);
        st.put_true(None);
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"b\": [ true, false, true ] }\n");
}

#[test]
fn int_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("k"));
        st.put_i64(None, 4);
        st.put_i64(None, 5);
        st.put_i64(None, 6);
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"k\": [ 4, 5, 6 ] }\n");
}

#[test]
fn real_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("r"));
        st.put_f64(None, 2.556, 3);
        st.put_f64(None, 3.7778, 4);
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"r\": [ 2.556, 3.7778 ] }\n");
}

#[test]
fn string_array() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("v"));
        st.put_cstr(None, Some("long"));
        st.put_cstr(None, Some("road"));
        st.close_array();
        st.close();
    }
    out_check(&js, "{ \"v\": [ \"long\", \"road\" ] }\n");
}

#[test]
fn int_array_int() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.put_i64(Some("a"), 7);
        st.open_array(Some("m"));
        st.close_array();
        st.put_i64(Some("b"), 8);
        st.close();
    }
    out_check(&js, "{ \"a\": 7, \"m\": [  ], \"b\": 8 }\n");
}

#[test]
fn string_array_string() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.put_cstr(Some("c"), Some("Snort"));
        st.open_array(Some("n"));
        st.close_array();
        st.put_cstr(Some("d"), Some("++"));
        st.close();
    }
    out_check(&js, "{ \"c\": \"Snort\", \"n\": [  ], \"d\": \"++\" }\n");
}

#[test]
fn root_array_of_objects() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open_array(None);
        st.open(None);
        st.close();
        st.open(None);
        st.close();
        st.open(None);
        st.close();
        st.close_array();
    }
    out_check(&js, "[ {  }, {  }, {  } ]\n");
}

#[test]
fn root_array_of_objects_with_nested() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open_array(None);
        st.open(None);
        st.put_i64(Some("i"), 1);
        st.open_array(Some("array_1"));
        st.open(None);
        st.put_cstr(Some("str"), Some("Snort"));
        st.close();
        st.open(None);
        st.put_cstr(Some("str"), Some("++"));
        st.close();
        st.close_array();
        st.put_i64(Some("j"), 2);
        st.close();
        st.open(None);
        st.put_i64(Some("i"), 3);
        st.open_array(Some("array_2"));
        st.open(None);
        st.put_cstr(Some("str"), Some("IPS"));
        st.close();
        st.open(None);
        st.put_cstr(Some("str"), Some("IDS"));
        st.close();
        st.close_array();
        st.put_i64(Some("j"), 4);
        st.close();
        st.close_array();
    }
    out_check(
        &js,
        "[ { \"i\": 1, \"array_1\": [ { \"str\": \"Snort\" }, { \"str\": \"++\" } ], \
\"j\": 2 }, { \"i\": 3, \"array_2\": [ { \"str\": \"IPS\" }, { \"str\": \"IDS\" } ], \
\"j\": 4 } ]\n",
    );
}

#[test]
fn root_object_with_nested() {
    let mut js = Js(Vec::new());
    {
        let mut st = js.stream();
        st.open(None);
        st.open_array(Some("keys"));
        st.put_cstr(None, Some("name"));
        st.put_cstr(None, Some("version"));
        st.close_array();
        st.open(Some("name"));
        st.put_cstr(Some("value"), Some("Snort"));
        st.close();
        st.open(Some("version"));
        st.put_cstr(Some("value"), Some("3.0.0"));
        st.close();
        st.close();
    }
    out_check(
        &js,
        "{ \"keys\": [ \"name\", \"version\" ], \"name\": { \"value\": \"Snort\" }, \
\"version\": { \"value\": \"3.0.0\" } }\n",
    );
}
