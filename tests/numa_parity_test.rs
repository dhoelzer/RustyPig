// Whole-transcript replay of tools/numa_harness/vectors.txt (C probe
// compiled from VERBATIM main/numa.cc) against the Rust port, plus a
// Rust translation of numa.cc's embedded [NUMA] UNIT_TEST cases.
use snort3::main::numa::*;

fn pn(p: u8) -> &'static str {
    match p {
        NUMA_POLICY_DEFAULT => "DEFAULT",
        NUMA_POLICY_PREFERRED => "PREFERRED",
        NUMA_POLICY_BIND => "BIND",
        NUMA_POLICY_LOCAL => "LOCAL",
        NUMA_POLICY_UNKNOWN => "UNKNOWN",
        _ => "OTHER",
    }
}

#[test]
fn numa_transcript_replay() {
    let mut got: Vec<String> = Vec::new();

    got.push(format!(
        "NUM {} {} {} {} {}",
        NUMA_POLICY_DEFAULT as u32,
        NUMA_POLICY_PREFERRED as u32,
        NUMA_POLICY_BIND as u32,
        NUMA_POLICY_LOCAL as u32,
        NUMA_POLICY_UNKNOWN as u32
    ));

    // probe table (exact): see probe.cc 'ins'
    let probe: [&str; 10] = [
        "default",
        "preferred",
        "bind",
        "local",
        "interleave",
        "preferred_many",
        "fake_policy",
        "Default",
        "",
        "bind ",
    ];
    for s in probe {
        let p = convert_string_to_numa_mempolicy(s);
        got.push(format!(
            "IN [{}] -> {} num={} back=[{}] same={}",
            s,
            pn(p),
            p as u32,
            stringify_numa_mempolicy(p),
            if stringify_numa_mempolicy(p) == s {
                1
            } else {
                0
            }
        ));
    }
    for v in [0u32, 1, 2, 3, 4, 5, 254, 255] {
        got.push(format!(
            "VAL {} -> [{}]",
            v,
            stringify_numa_mempolicy(v as u8)
        ));
    }
    got.push("DONE".to_string());

    let want = std::str::from_utf8(include_bytes!("../tools/numa_harness/vectors.txt"))
        .expect("vectors utf8");
    assert_eq!(
        want.trim_end_matches('\n'),
        got.join("\n"),
        "transcript replay mismatch"
    );
}

#[test]
fn numa_unit_test_positive_negative_stringify() {
    // embedded UNIT_TEST "Parse string to NumaMemPolicy positive test"
    assert_eq!(convert_string_to_numa_mempolicy("default"), NUMA_POLICY_DEFAULT);
    assert_eq!(
        convert_string_to_numa_mempolicy("preferred"),
        NUMA_POLICY_PREFERRED
    );
    assert_eq!(convert_string_to_numa_mempolicy("bind"), NUMA_POLICY_BIND);
    assert_eq!(convert_string_to_numa_mempolicy("local"), NUMA_POLICY_LOCAL);

    // "Parse string to NumaMemPolicy negative test"
    assert_eq!(
        convert_string_to_numa_mempolicy("preferred_many"),
        NUMA_POLICY_UNKNOWN
    );
    assert_eq!(
        convert_string_to_numa_mempolicy("interleave"),
        NUMA_POLICY_UNKNOWN
    );
    assert_eq!(
        convert_string_to_numa_mempolicy("fake_policy"),
        NUMA_POLICY_UNKNOWN
    );

    // "Parse NumaMemPolicy to string"
    assert_eq!(stringify_numa_mempolicy(NUMA_POLICY_DEFAULT), "default");
    assert_eq!(stringify_numa_mempolicy(NUMA_POLICY_PREFERRED), "preferred");
    assert_eq!(stringify_numa_mempolicy(NUMA_POLICY_BIND), "bind");
    assert_eq!(stringify_numa_mempolicy(NUMA_POLICY_LOCAL), "local");
    assert_eq!(stringify_numa_mempolicy(NUMA_POLICY_UNKNOWN), "unknown");
}
