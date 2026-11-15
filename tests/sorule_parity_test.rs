// Whole-transcript replay of tools/sorule_harness/vectors.txt: the C
// harness compiled ORIGINAL parser/parse_so_rule.cc twice -- once through
// the upstream Catch2 tables as a semantic gate, once merged with a probe
// that drives parse_so_rule (full stub+opts channels) and get_so_stub over
// every upstream table input plus extras. This test replays the identical
// inputs and compares escaped IN/R/STUB/OPTS/GETSTUB lines + banners
// byte-for-byte.
use snort3::parser::parse_so_rule::{get_so_stub, parse_so_rule};

fn esc(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            0x20..=0x7e => out.push(*b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Unescape vectors IN lines back to raw C strings.
fn unesc(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
            let hi = (b[i + 2] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 3] as char).to_digit(16).unwrap() as u8;
            out.push(hi * 16 + lo);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn sorule_transcript_parity() {
    let want = include_str!("../tools/sorule_harness/vectors.txt");

    // section -> Vec<raw input> straight from the IN lines
    let mut sections: Vec<(&str, Vec<String>)> = Vec::new();
    for line in want.lines() {
        if let Some(inp) = line.strip_prefix("IN ") {
            if sections.is_empty() {
                panic!("IN line before any banner");
            }
            sections.last_mut().unwrap().1.push(unesc(inp));
        } else if line.starts_with("=== ") {
            sections.push((line, Vec::new()));
        }
    }

    let mut got = String::new();
    for (banner, inputs) in &sections {
        got.push_str(banner);
        got.push('\n');
        let via_public = banner.contains("get_so_stub parity");
        for raw in inputs {
            if via_public {
                let mut stub = String::new();
                let r = get_so_stub(raw, &mut stub);
                got.push_str(&format!("IN {}\n", esc(raw)));
                got.push_str(&format!("GETSTUB {} [{}]\n", i32::from(r), esc(&stub)));
            } else {
                let mut stub = String::new();
                let mut opts = String::new();
                let r = parse_so_rule(raw, &mut stub, &mut opts);
                got.push_str(&format!("IN {}\n", esc(raw)));
                got.push_str(&format!(
                    "R {} STUB [{}] OPTS [{}]\n",
                    i32::from(r),
                    esc(&stub),
                    esc(&opts)
                ));
            }
        }
    }

    if got != want {
        let g: Vec<&str> = got.lines().collect();
        let w: Vec<&str> = want.lines().collect();
        let mut shown = 0;
        for i in 0..g.len().max(w.len()) {
            let a = g.get(i).copied().unwrap_or("<eof>");
            let b = w.get(i).copied().unwrap_or("<eof>");
            if a != b {
                eprintln!(
                    "line {}:
  rust={}
  c   ={}",
                    i + 1,
                    a.chars().take(100).collect::<String>(),
                    b.chars().take(100).collect::<String>()
                );
                shown += 1;
                if shown >= 8 {
                    break;
                }
            }
        }
        panic!(
            "sorule transcript mismatch (rust {} lines, c {} lines)",
            g.len(),
            w.len()
        );
    }
    assert_eq!(want.lines().count(), 152);
}
