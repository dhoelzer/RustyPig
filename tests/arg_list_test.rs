//! Replay of tools/arglist_harness/vectors.txt (probe over original
//! arg_list.cc; no upstream suite). Pins the FIXIT-L "-n -4" behavior,
//! empty-pending "---" flush, bare "-", attached short-opt values, first-'='
//! long-opt split, and argv[0]-skip semantics.

use snort3::parser::arg_list::ArgList;

#[test]
fn replay_vectors() {
    let body = include_str!("../tools/arglist_harness/vectors.txt");
    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0;
    let mut cases = 0;
    while i < lines.len() {
        let line = lines[i];
        let rest = line
            .strip_prefix("ARGV ")
            .unwrap_or_else(|| panic!("expected ARGV, got {line}"));
        // parse bracketed tokens "[tok]"
        let mut argv: Vec<Vec<u8>> = Vec::new();
        let mut j = 0usize;
        let bytes = rest.as_bytes();
        while j < bytes.len() {
            if bytes[j] == b'[' {
                let end = rest[j..].find(']').unwrap() + j;
                argv.push(rest.as_bytes()[j + 1..end].to_vec());
                j = end + 1;
            } else {
                j += 1;
            }
        }
        i += 1;
        cases += 1;

        let mut al = ArgList::new(&argv);
        loop {
            if i >= lines.len() {
                panic!("vectors truncated");
            }
            let want = lines[i];
            i += 1;
            if want == "GA end" {
                assert_eq!(al.get_arg(), None, "argv {argv:?}");
                break;
            }
            let got = al
                .get_arg()
                .unwrap_or_else(|| panic!("argv {argv:?}: expected {want}"));
            let got_str = format!(
                "GA ({})=({})",
                String::from_utf8_lossy(&got.0),
                String::from_utf8_lossy(&got.1)
            );
            assert_eq!(got_str, want, "argv {argv:?}");
        }
    }
    assert!(cases >= 16, "{cases}");
}

#[test]
fn reset_replays() {
    let argv = ["prog", "-i", "eth0"];
    let mut al = ArgList::new(&argv);
    let first = al.get_arg().unwrap();
    assert_eq!((first.0.as_slice(), first.1.as_slice()), (b"i".as_slice(), b"eth0".as_slice()));
    assert!(al.get_arg().is_none());
    al.reset();
    assert!(al.get_arg().is_some());
}
