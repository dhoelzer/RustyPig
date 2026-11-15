//! Port of the UNIT_TEST Catch2 suite embedded in framework/ips_option.cc
//! (1 TEST_CASE, 3 SECTION levels: == test, hash short, hash long).
use snort3::framework::pdu_section::*;
use snort3::framework::ips_option::*;

const LONG: &str = "101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101\
101010101010101010101010101010101010101010101010101010101010101";

#[test]
fn ips_option_eq_test() {
    let main_ips = IpsOption::new("ips_test", OptionType::Other);

    let case_diff_name = IpsOption::new("not_hello_world", OptionType::LeafNode);
    assert!(!main_ips.option_eq(&case_diff_name));

    let case_diff_option = IpsOption::new("hello_world", OptionType::Content);
    assert!(!main_ips.option_eq(&case_diff_option));

    // same name would be equal; C test passes hello_world vs ips_test
    // with type OTHER and still expects false (different names).
    let case_option_na = IpsOption::new("hello_world", OptionType::Other);
    assert!(!main_ips.option_eq(&case_option_na));
}

#[test]
fn ips_option_hash_short() {
    let other_main_ips = IpsOption::new("ips_test", OptionType::Other);
    let main_ips_short = IpsOption::new("ips_test", OptionType::Other);
    let main_ips_short_diff = IpsOption::new("not_ips_test", OptionType::Other);

    assert_eq!(other_main_ips.hash(), main_ips_short.hash());
    assert_ne!(other_main_ips.hash(), main_ips_short_diff.hash());
}

#[test]
fn ips_option_hash_long() {
    let main_ips = IpsOption::new("ips_test", OptionType::Other);

    let first = IpsOption::new(LONG, OptionType::Other);
    let second = IpsOption::new(LONG, OptionType::Other);
    assert_eq!(first.hash(), second.hash());
    assert_ne!(first.hash(), main_ips.hash());
}

/// Pin the hash values themselves against the C++ harness ground truth:
/// MS lines in tools/hash_harness/vectors.txt carry (a,b,c) for mix_str
/// + finalize; IpsOption::hash returns c.
#[test]
fn ips_option_hash_values_pin_cpp() {
    let txt = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tools/hash_harness/vectors.txt"
    ))
    .unwrap();
    for (name, ips) in [
        ("ips_test", "ips_test"),
        ("not_ips_test", "not_ips_test"),
        ("hello_world", "hello_world"),
        ("not_hello_world", "not_hello_world"),
    ] {
        let line = txt
            .lines()
            .find(|l| l == &format!("MS {name} 0 0 0") || l.starts_with(&format!("MS {name} ")))
            .unwrap_or_else(|| panic!("no MS line for {name}"));
        let fields: Vec<&str> = line.split(' ').collect();
        let want_c: u32 = fields[4].parse().unwrap();
        assert_eq!(IpsOption::new(ips, OptionType::Other).hash(), want_c, "hash({name})");
    }
}

#[test]
fn pdu_section_defaults() {
    // C get_pdu_section(bool) default for plain options
    assert_eq!(IpsOption::default_pdu_section(), 1); // 1 << PS_NONE
    assert_eq!(section_to_flag(PduSection::PsHeader), 2);
    assert_eq!(section_to_flag(PduSection::PsTrailer), 16);
    assert_eq!(PS_MAX, 4); // PS_MAX == PS_TRAILER
}

#[test]
fn ipsapi_version_pin() {
    // (BASE_API_VERSION 29 << 16) | 4
    assert_eq!(IPSAPI_VERSION, (29u32 << 16) | 4);
}
