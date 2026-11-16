// Whole-transcript replay of tools/jsnorm_harness/vectors.txt (the
// ORIGINAL utils/util_jsnorm.cc compiled verbatim) plus the TU's two
// embedded [util_jsnorm] Catch cases translated to Rust assertions.
// The transcript is the ground truth; this test pins the Rust port to
// it byte-for-byte (hex-decoded outputs compared as bytes because
// normalized output contains raw 0xff).
//
// vectors md5: c239efde570730af672142f77dba6bc6 (21 lines, stable
// across double builds).
use snort3::utils::jsnorm::{js_normalize_decode, JsState};

const VECTORS: &str = include_str!("../tools/jsnorm_harness/vectors.txt");

/// The probe's `norm()` helper shape (allowed_spaces=200,
/// allowed_levels=MAX_ALLOWED_OBFUSCATION=1, zeroed 256-byte out).
fn norm(script: &[u8], destcap: usize) -> (i32, i32, usize, u16, Vec<u8>) {
    let mut out = vec![0u8; 256];
    let mut js = JsState {
        allowed_spaces: 200,
        allowed_levels: 1,
        alerts: 0,
    };
    let mut ptr = 0usize;
    let mut bcopied = 0i32;
    let rc =
        js_normalize_decode(script, script.len(), &mut out, destcap, &mut ptr, &mut bcopied, Some(&mut js), None);
    let n = usize::try_from(bcopied).unwrap_or(0).min(out.len());
    (rc, bcopied, ptr, js.alerts, out[..n].to_vec())
}

type RunFn = fn(&[u8], usize) -> (i32, i32, usize, u16, Vec<u8>);

struct Case {
    name: &'static str,
    script: Vec<u8>,
    destcap: usize,
    // Some(f) = the probe emitted this vector through an inline
    // block (custom js/map/cap), not the plain norm() helper.
    run: Option<RunFn>,
}

fn umap() -> Vec<u8> {
    let mut m = vec![0u8; 256];
    m[0x41] = 1;
    m
}

fn n17(s: &[u8], cap: usize) -> (i32, i32, usize, u16, Vec<u8>) {
    let mut out = vec![0u8; 64];
    let mut js = JsState { allowed_spaces: 200, allowed_levels: 1, alerts: 0 };
    let map = umap();
    let mut ptr = 0usize;
    let mut bc = 0i32;
    let rc = js_normalize_decode(s, s.len(), &mut out, cap, &mut ptr, &mut bc, Some(&mut js), Some(&map));
    let n = usize::try_from(bc).unwrap_or(0).min(out.len());
    (rc, bc, ptr, js.alerts, out[..n].to_vec())
}

fn n12(_s: &[u8], _cap: usize) -> (i32, i32, usize, u16, Vec<u8>) {
    // probe: JSNormalizeDecode("x", 1, out, 64, &p, &bc, nullptr,
    // nullptr) -- C's null-js contract returns RET_QUIT before
    // touching ptr or bytes_copied; probe reports bc=0, ptr delta 0.
    let mut out = vec![0u8; 64];
    let mut ptr = 0usize;
    let mut bc = 0i32;
    let rc = js_normalize_decode(b"x", 1, &mut out, 64, &mut ptr, &mut bc, None, None);
    (rc, bc, ptr, 0, Vec::new())
}

#[test]
fn jsnorm_transcript_replay() {
    let sp_x: Vec<u8> = {
        let mut v = vec![b' '; 250];
        v.push(b'x');
        v
    };
    let cases: Vec<Case> = vec![
        Case { name: "UP1", script: b"unescape('\xff%41')".to_vec(), destcap: 64, run: None },
        Case { name: "UP2", script: b"String.fromCharCode(65,\xff)".to_vec(), destcap: 64, run: None },
        Case { name: "N3", script: b"unescape(unescape('%25ff'))".to_vec(), destcap: 64, run: None },
        Case { name: "N4", script: b"unescape(unescape(unescape('%2525ff')))".to_vec(), destcap: 64, run: None },
        Case { name: "N5", script: b"a  b\t\tc   d".to_vec(), destcap: 64, run: None },
        Case { name: "N6", script: sp_x, destcap: 64, run: None },
        Case { name: "N7", script: b"'a  b'  \"c  d\"  e".to_vec(), destcap: 64, run: None },
        Case { name: "N8a", script: b"unescape(".to_vec(), destcap: 64, run: None },
        Case { name: "N8b", script: b"unescape(\"".to_vec(), destcap: 64, run: None },
        Case { name: "N8c", script: b"String.fromCharCode(65".to_vec(), destcap: 64, run: None },
        Case {
            name: "N9",
            script: b"String.fromCharCode(0x41,101,66,66,09,0XX)".to_vec(),
            destcap: 64,
            run: None,
        },
        Case { name: "N10a", script: b"unescape('%u0041%u0042')".to_vec(), destcap: 64, run: None },
        Case { name: "N10b", script: b"unescape('%41%u0042')".to_vec(), destcap: 64, run: None },
        Case { name: "N11", script: b"unescape('%41%42%43%44%45%46')".to_vec(), destcap: 3, run: None },
        Case { name: "N12", script: Vec::new(), destcap: 0, run: Some(n12) },
        Case { name: "N13", script: Vec::new(), destcap: 64, run: None },
        Case { name: "N14", script: b"a\0b".to_vec(), destcap: 64, run: None },
        Case { name: "N15", script: b"unescape('%41+B')".to_vec(), destcap: 64, run: None },
        Case { name: "N16", script: b"unescape('%25%35%35')".to_vec(), destcap: 64, run: None },
        Case { name: "N17", script: b"unescape('%u0041')".to_vec(), destcap: 64, run: Some(n17) },
    ];

    let mut got = String::new();
    for c in &cases {
        let (rc, co, pt, al, out) = match c.run {
            Some(f) => f(&c.script, c.destcap),
            None => norm(&c.script, c.destcap),
        };
        got.push_str(&format!("<N>{}<RC>{}<CO>{}<PT>{}<AL>{}<HX>", c.name, rc, co, pt, al));
        for b in &out {
            got.push_str(&format!("{b:02x}"));
        }
        got.push_str("<NE>\n");
    }
    got.push_str("DONE\n");

    // byte-exact whole-transcript compare
    assert_eq!(got, VECTORS, "jsnorm transcript mismatch");
}

// The TU's embedded [util_jsnorm] Catch cases (normalize_script
// helper shape: char out[64] zeroed, decode, string(out, copied)).
fn normalize_script(script: &[u8]) -> Vec<u8> {
    let (rc, _co, _pt, _al, out) = norm(script, 64);
    assert_eq!(rc, 0);
    out
}

#[test]
fn upstream_unescape_0xff_case() {
    assert_eq!(normalize_script(b"unescape('\xff%41')"), b"'\xffA'");
}

#[test]
fn upstream_sfcc_0xff_case() {
    assert_eq!(normalize_script(b"String.fromCharCode(65,\xff)"), b"A\xff)");
}
