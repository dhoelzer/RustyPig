//! Parity test replaying tools/unfold_harness/vectors.txt — ground truth
//! produced by compiling the ORIGINAL util_unfold.cc (sf_strip_CRLF and
//! sf_strip_LWS have no upstream unit tests; see build.sh).
use snort3::utils::util_unfold::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn unfold_strip_parity_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/unfold_harness/vectors.txt");
    let content = std::fs::read_to_string(path).expect("vectors.txt; run tools/unfold_harness/build.sh");

    let mut cases = 0;
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        // CASE <tag> in=<hex> ocap=N ret=R ob=O out=<hex>
        let rest = line.strip_prefix("CASE ").unwrap();
        let tag = rest.split_whitespace().next().unwrap();
        let between = rest.split_once("in=<").unwrap().1;
        let in_hex = between.split_once(">").unwrap().0;
        let after = &between.split_once(">").unwrap().1;
        let ocap: usize = after
            .split_whitespace()
            .find(|t| t.starts_with("ocap="))
            .unwrap()[5..]
            .parse()
            .unwrap();
        let want_ret: i32 = after
            .split_whitespace()
            .find(|t| t.starts_with("ret="))
            .unwrap()[4..]
            .parse()
            .unwrap();
        let want_ob: u32 = after
            .split_whitespace()
            .find(|t| t.starts_with("ob="))
            .unwrap()[3..]
            .parse()
            .unwrap();
        let out_hex = after.split_once("out=<").unwrap().1.split_once('>').unwrap().0;

        let input = unhex(in_hex);
        // mimic C's fixed-capacity buffer: exactly ocap bytes, poisoned so
        // we see every byte the original touched
        if ocap == 0 {
            continue; // C UB with a zero-size buffer; no vector uses it
        }
        let mut buf = vec![0xAAu8; ocap];

        let (ret, ob) = if tag == "crlf" {
            sf_strip_crlf(&input, &mut buf)
        } else {
            sf_strip_lws(&input, &mut buf)
        };

        assert_eq!(ret, want_ret, "{line}");
        let ob = ob.expect("output_bytes requested in harness");
        assert_eq!(ob, want_ob, "{line}");

        let n = (ob as usize).min(ocap);
        assert_eq!(hex(&buf[..n]), out_hex, "{line}");
        cases += 1;
    }
    assert!(cases >= 20, "expected 20 vector cases, got {cases}");
}
