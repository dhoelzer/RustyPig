// Port of snort3 helpers/json_stream.{h,cc} (Copyright (C) 2020-2026 Cisco).
//
// JsonStream writes JSON to any Write sink (C: std::ostream&). Byte-level
// escaping identical to the C original: escape only " \ b f n r t and
// non-isprint bytes (C locale isprint = 0x20..0x7E) as lowercase \u00xx.
// std::quoted(key) becomes quoted(): wraps in '"' escaping '"' and '\\'.

#![allow(dead_code)]

use std::io::Write;

/// C str_esc_pos + escape_json_append on a byte slice (C is byte-oriented;
/// UTF-8 multi-byte sequences are escaped byte-by-byte, matching C).
pub fn escape_json_append(out: &mut String, v: &[u8]) {
    if v.is_empty() {
        return;
    }
    let pos = str_esc_pos(v);
    if pos != 0 {
        // bytes before pos are all printable ASCII (0x20..0x7E) -> valid UTF-8
        out.push_str(std::str::from_utf8(&v[..pos]).unwrap_or(""));
    }
    if pos == v.len() {
        return;
    }
    let rest = &v[pos..];

    for &c in rest {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => {
                if (0x20..=0x7e).contains(&c) {
                    out.push(c as char);
                } else {
                    out.push_str(&format!("\\u{c:04x}"));
                }
            }
        }
    }
}

fn str_esc_pos(s: &[u8]) -> usize {
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'\\' | b'"' | 0x08 | 0x0c | b'\n' | b'\r' | b'\t' => return i,
            _ => {
                if !(0x20..=0x7e).contains(&c) {
                    return i;
                }
            }
        }
    }
    s.len()
}

/// C std::quoted(key): quote, escaping '"' and '\\'.
fn quoted(w: &mut dyn Write, key: &str) {
    w.write_all(b"\"").unwrap();
    for &c in key.as_bytes() {
        if c == b'"' || c == b'\\' {
            w.write_all(b"\\").unwrap();
        }
        w.write_all(&[c]).unwrap();
    }
    w.write_all(b"\"").unwrap();
}

pub struct JsonStream<'a> {
    out: &'a mut dyn Write,
    sep: bool,
    level: u32,
    level_array: u32,
    // C++ keeps fixed+precision sticky on the ostream once set; each
    // double put applies them explicitly, matching observable output.
}

impl<'a> JsonStream<'a> {
    pub fn new(out: &'a mut dyn Write) -> Self {
        JsonStream {
            out,
            sep: false,
            level: 0,
            level_array: 0,
        }
    }

    fn emit(&mut self, s: &[u8]) {
        self.out.write_all(s).unwrap();
    }

    pub fn open(&mut self, key: Option<&str>) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        self.emit(b"{ ");
        self.sep = false;
        self.level += 1;
    }

    pub fn close(&mut self) {
        self.emit(b" }");
        self.sep = true;
        assert!(self.level > 0);
        self.level -= 1;
        if self.level == 0 && self.level_array == 0 {
            self.emit(b"\n");
            self.sep = false;
        }
    }

    pub fn open_array(&mut self, key: Option<&str>) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        self.emit(b"[ ");
        self.sep = false;
        self.level_array += 1;
    }

    pub fn close_array(&mut self) {
        self.emit(b" ]");
        self.sep = true;
        assert!(self.level_array > 0);
        self.level_array -= 1;
        if self.level_array == 0 && self.level == 0 {
            self.emit(b"\n");
            self.sep = false;
        }
    }

    pub fn put_null(&mut self, key: Option<&str>) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        self.emit(b"null");
    }

    pub fn put_i64(&mut self, key: Option<&str>, val: i64) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        let s = val.to_string();
        self.emit(s.as_bytes());
    }

    pub fn uput_u64(&mut self, key: Option<&str>, val: u64) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        let s = val.to_string();
        self.emit(s.as_bytes());
    }

    /// C put(key, const char*): empty c-string writes nothing; null writes
    /// null. Option<&str> models both.
    pub fn put_cstr(&mut self, key: Option<&str>, val: Option<&str>) {
        if let Some(v) = val {
            if v.is_empty() {
                return;
            }
            self.split();
            if let Some(k) = key {
                quoted(self.out, k);
                self.emit(b": ");
            }
            self.emit(b"\"");
            let mut esc = String::new();
            escape_json_append(&mut esc, v.as_bytes());
            self.emit(esc.as_bytes());
            self.emit(b"\"");
        } else {
            self.split();
            if let Some(k) = key {
                quoted(self.out, k);
                self.emit(b": ");
            }
            self.emit(b"null");
        }
    }

    /// C put(key, const std::string&): empty string writes nothing.
    pub fn put_string_q(&mut self, key: Option<&str>, val: &str) {
        if val.is_empty() {
            return;
        }
        self.put_string(key, val);
    }

    /// C put_string(): always writes, even empty.
    pub fn put_string(&mut self, key: Option<&str>, val: &str) {
        self.put_string_bytes(key, val.as_bytes());
    }

    /// Byte-faithful entry for C `std::string` inputs that are not
    /// valid UTF-8 (C strings are byte containers; the escape layer
    /// already works on bytes). Same body as put_string.
    pub fn put_string_bytes(&mut self, key: Option<&str>, val: &[u8]) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        self.emit(b"\"");
        let mut esc = String::new();
        escape_json_append(&mut esc, val);
        self.emit(esc.as_bytes());
        self.emit(b"\"");
    }

    /// C put(key, double, precision): std::fixed with precision.
    pub fn put_f64(&mut self, key: Option<&str>, val: f64, precision: usize) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        // C++ iostream fixed+precision rounds the same as printf %.*f
        let s = format!("{:.*}", precision, val);
        self.emit(s.as_bytes());
    }

    pub fn put_true(&mut self, key: Option<&str>) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        self.emit(b"true");
    }

    pub fn put_false(&mut self, key: Option<&str>) {
        self.split();
        if let Some(k) = key {
            quoted(self.out, k);
            self.emit(b": ");
        }
        self.emit(b"false");
    }

    fn split(&mut self) {
        if self.sep {
            self.emit(b", ");
        } else {
            self.sep = true;
        }
    }

    pub fn put_eol(&mut self) {
        self.emit(b"\n");
    }
}
