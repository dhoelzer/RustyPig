// Port of src/sfip/test/sf_ip_test.cc — the FuncTest table (kept 1:1 with the
// original rows, including the deliberately quirky expectations) and the three
// Catch checks: FuncCheck / SetCheck / CopyCheck plus "uri parsing".

use snort3::sfip::sf_cidr::SfCidr;
use snort3::sfip::sf_ip::*;
use snort3::sfip::sf_returns::*;

struct FuncTest {
    func: &'static str,
    arg1: &'static str,
    arg2: Option<&'static str>,
    expected: SfIpRet,
}

macro_rules! ft {
    ($f:expr, $a1:expr, $a2:expr, $e:expr) => {
        FuncTest { func: $f, arg1: $a1, arg2: Some($a2), expected: $e }
    };
}
macro_rules! ft1 {
    ($f:expr, $a1:expr, $e:expr) => {
        FuncTest { func: $f, arg1: $a1, arg2: None, expected: $e }
    };
}

const SUCCESS: SfIpRet = SfIpRet::Success;
const FAILURE: SfIpRet = SfIpRet::Failure;
const LESSER: SfIpRet = SfIpRet::Lesser;
const GREATER: SfIpRet = SfIpRet::Greater;
const EQUAL: SfIpRet = SfIpRet::Equal;
const CONTAINS: SfIpRet = SfIpRet::Contains;
const NOT_CONTAINS: SfIpRet = SfIpRet::NotContains;

fn ftests() -> Vec<FuncTest> {
    vec![
        ft!("sfip_pton", "192.168.0.1", "192.168.0.1", SUCCESS),
        ft!("sfip_pton", "255.255.255.255/21", "255.255.248.0", SUCCESS),
        ft!("sfip_pton", "1.1.255.255      255.255.248.0", "1.1.248.0", SUCCESS),
        ft!("sfip_pton", " 2001:0db8:0000:0000:0000:0000:1428:57ab   ",
            "2001:0db8:0000:0000:0000:0000:1428:57ab", SUCCESS),
        ft!("sfip_pton", "ffff:ffff::1",
            "ffff:ffff:0000:0000:0000:0000:0000:0001", SUCCESS),
        ft!("sfip_pton", "fFfF::FfFf:FFFF/127",
            "ffff:0000:0000:0000:0000:0000:ffff:fffe", SUCCESS),
        ft!("sfip_pton", "ffff::ffff:1/8",
            "ff00:0000:0000:0000:0000:0000:0000:0000", SUCCESS),
        ft!("sfip_pton", "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::",
            "6543:2100:0000:0000:0000:0000:0000:0000", SUCCESS),
        ft!("sfip_pton", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
            "ffee:ddcc:0000:0000:0000:0000:0000:0000", SUCCESS),
        ft!("sfip_pton", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100",
            "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", SUCCESS),
        ft!("sfip_pton", "1.2.3.4:255.0.0.0", "1.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4/255.0.0.0", "1.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4 : 255.0.0.0", "1.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4 / 255.0.0.0", "1.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4  :255.0.0.0", "1.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4/  255.0.0.0", "1.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4/16", "1.2.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4/ 16", "1.2.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4 / 16", "1.2.0.0", SUCCESS),
        ft!("sfip_pton", " 1.2.3.4 / 16 ", "1.2.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4/0", "0.0.0.0", SUCCESS),
        ft!("sfip_pton", "1.2.3.4/16", "1.2.0.0", SUCCESS),
        ft!("sfip_pton", "1234::1.2.3.4",
            "1234:0000:0000:0000:0000:0000:0102:0304", SUCCESS),
        ft!("sfip_pton", "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210",
            "fedc:ba98:7654:3210:fedc:ba98:7654:3210", SUCCESS),
        ft!("sfip_pton", "1080:0:0:0:8:800:200C:4171",
            "1080:0000:0000:0000:0008:0800:200c:4171", SUCCESS),
        ft!("sfip_pton", "3ffe:2a00:100:7031::1",
            "3ffe:2a00:0100:7031:0000:0000:0000:0001", SUCCESS),
        ft!("sfip_pton", "1080::8:800:200C:417A",
            "1080:0000:0000:0000:0008:0800:200c:417a", SUCCESS),
        ft!("sfip_pton", "::192.9.5.5",
            "0000:0000:0000:0000:0000:0000:c009:0505", SUCCESS),
        ft!("sfip_pton", "::FFFF:129.144.52.38",
            "0000:0000:0000:0000:0000:ffff:8190:3426", SUCCESS),
        ft!("sfip_pton", "2010:836B:4179::836B:4179",
            "2010:836b:4179:0000:0000:0000:836b:4179", SUCCESS),
        ft!("sfip_pton", "::", "0000:0000:0000:0000:0000:0000:0000:0000", SUCCESS),

        ft1!("sfip_is_set", "8::", SUCCESS),
        ft1!("sfip_is_set", "::1", SUCCESS),
        ft1!("sfip_is_set", "::", FAILURE),

        ft1!("sfip_is_loopback", "127.0.0.0", SUCCESS),
        ft1!("sfip_is_loopback", "127.255.255.255", SUCCESS),
        ft1!("sfip_is_loopback", "128.0.0.0", FAILURE),
        ft1!("sfip_is_loopback", "::1", SUCCESS),
        ft1!("sfip_is_loopback", "::2", FAILURE),
        ft1!("sfip_is_loopback", "::7f00:0/104", SUCCESS),
        ft1!("sfip_is_loopback", "::ffff:127.0.0.0/104", SUCCESS),
        ft1!("sfip_is_loopback", "::127.0.0.0", SUCCESS),
        ft1!("sfip_is_loopback", "::128.0.0.1", FAILURE),
        ft1!("sfip_is_loopback", "::ffff:0.0.0.1", FAILURE),

        ft1!("sfip_ismapped", "::ffff:c000:280", SUCCESS),
        ft1!("sfip_ismapped", "8::ffff:c000:280", FAILURE),
        ft1!("sfip_ismapped", "::fffe:c000:280", FAILURE),

        // v6<->v6 Comparisons
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", EQUAL),
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "1:1:3:4:5:6:7:8", GREATER),
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "1:2:4:4:5:6:7:8", LESSER),
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:5:7:8", GREATER),
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:8:8", LESSER),

        ft!("sfip_compare", "1.2.3.4", "1.2.3.4", EQUAL),
        ft!("sfip_compare", "255.255.255.255", "192.168.0.1", GREATER),
        ft!("sfip_compare", "192.168.0.1", "255.255.255.255/21", LESSER),
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", EQUAL),
        ft!("sfip_compare", "ffff:ffff::1",
            "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::", GREATER),
        ft!("sfip_compare", "1.2.3.4", "0.0.0.0", EQUAL),
        ft!("sfip_compare", "1:2:3:4:5:6:7:8", "::", EQUAL),
        ft!("sfip_compare", "10.10.1.0/16", "10.10.24.14/24", LESSER),
        ft!("sfip_compare", "10.10.1.0/24", "10.10.1.0/16", GREATER),
        ft!("sfip_compare", "10.10.1.0/16", "10.10.2.1/8", GREATER),
        ft!("sfip_compare", "10.10.1.8/32", "10.10.1.8", EQUAL),

        ft!("sfip_compare_unset", "1.2.3.4", "1.2.3.4", EQUAL),
        ft!("sfip_compare_unset", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", EQUAL),
        ft!("sfip_compare_unset", "1.2.3.4", "0.0.0.0", FAILURE),
        ft!("sfip_compare_unset", "1:2:3:4:5:6:7:8", "::", FAILURE),

        ft!("sfip_fast_eq4", "1.2.3.4", "1.2.3.4", SUCCESS),
        ft!("sfip_fast_eq4", "1.2.3.4", "1.2.3.5", FAILURE),
        ft!("sfip_fast_eq4", "1.2.3.5", "1.2.3.4", FAILURE),

        ft!("sfip_fast_lt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", FAILURE),
        ft!("sfip_fast_lt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", SUCCESS),
        ft!("sfip_fast_lt6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", FAILURE),

        ft!("sfip_fast_gt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", FAILURE),
        ft!("sfip_fast_gt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", FAILURE),
        ft!("sfip_fast_gt6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", SUCCESS),

        ft!("sfip_fast_eq6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SUCCESS),
        ft!("sfip_fast_eq6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", FAILURE),
        ft!("sfip_fast_eq6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", FAILURE),

        ft!("sfip_fast_cont4", "255.255.255.255", "192.168.0.1", FAILURE),
        ft!("sfip_fast_cont4", "192.168.0.1", "255.255.255.255/21", FAILURE),
        ft!("sfip_fast_cont4", "255.255.255.255/21", "255.255.255.255", SUCCESS),
        ft!("sfip_fast_cont4", "255.255.255.255", "255.255.255.255/21", FAILURE),

        ft!("sfip_contains", "255.255.255.255", "192.168.0.1", NOT_CONTAINS),
        ft!("sfip_contains", "192.168.0.1", "255.255.255.255/21", NOT_CONTAINS),
        ft!("sfip_contains", "255.255.255.255/21", "255.255.255.255", CONTAINS),
        ft!("sfip_contains", "255.255.255.255", "255.255.255.255/21", NOT_CONTAINS),
        ft!("sfip_contains", "10.10.1.0/16", "10.10.24.14/24", CONTAINS),
        ft!("sfip_contains", "10.10.1.0/16", "10.10.1.0/24", CONTAINS),
        ft!("sfip_contains", "10.10.1.0/16", "10.10.2.1/8", NOT_CONTAINS),
        ft!("sfip_contains", "10.10.1.8/32", "10.10.1.8", CONTAINS),

        ft!("sfip_fast_cont6", "ffff:ffff::1", "ffff::ffff:1/8", FAILURE),
        ft!("sfip_fast_cont6", "ffff::ffff:1/8", "ffff:ffff::1", SUCCESS),
        ft!("sfip_fast_cont6", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
            "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", SUCCESS),
        ft!("sfip_fast_cont6", "1001:db8:85a3::/28", "1001:db0::", SUCCESS),
        ft!("sfip_fast_cont6", "1001:db8:85a3::/29", "1001:db0::", FAILURE),

        ft!("sfip_contains", "ffff:ffff::1", "ffff::ffff:1/8", NOT_CONTAINS),
        ft!("sfip_contains", "ffff::ffff:1/8", "ffff:ffff::1", CONTAINS),
        ft!("sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
            "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", CONTAINS),
        ft!("sfip_contains", "1001:db8:85a3::/28", "1001:db0::", CONTAINS),
        ft!("sfip_contains", "1001:db8:85a3::/29", "1001:db0::", NOT_CONTAINS),

        ft!("sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101",
            "ffee:ddcc:bbaa:9988:7766:5544:3322:1102", NOT_CONTAINS),
        ft!("sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101/96",
            "ffee:ddcc:bbaa:9988:7766:5544:3322:1102", CONTAINS),
        ft!("sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101/97",
            "ffee:ddcc:bbaa:9988:7766:5544:3322:1102", CONTAINS),
        ft!("sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101/97",
            "ffee:ddcc:bbaa:9988:7766:5544:b322:1102", NOT_CONTAINS),

        ft!("sfip_contains", "255.255.255.255",
            "2001:0db8:0000:0000:0000:0000:1428:57ab", NOT_CONTAINS),

        ft!("sfip_obfuscate", "::", "0000:0000:0000:0000:0000:0000:0000:0000", EQUAL),
        ft!("sfip_obfuscate", "::/64",
            "0000:0000:0000:0000:0004:0003:0002:0001", EQUAL),
        ft!("sfip_obfuscate", "f0:e0:d0:c0::8/64",
            "00f0:00e0:00d0:00c0:0004:0003:0002:0001", EQUAL),
        ft!("sfip_obfuscate", "9.8.7.6", "9.8.7.6", EQUAL),
        ft!("sfip_obfuscate", "0.0.0.8/16", "0.0.2.1", EQUAL),
        ft!("sfip_obfuscate", "192.168.0.0/16", "192.168.2.1", EQUAL),
    ]
}

/// RunFunc mirrors the C++ test driver (CATCH variant): test_features = true,
/// i.e. full-length ntop with %04x groups / simple decimal v4.
fn run_func(func: &str, arg1: &str, arg2: Option<&str>) -> (i32, SfIpRet) {
    // returns (success-as-int for bool-style funcs, SfIpRet for enum-style);
    // the C++ returns int mixing both — we track the enum result and map.
    let mut cidr1 = SfCidr::new();
    if !arg1.is_empty() {
        cidr1.set_str(arg1);
    }
    let cidr2_empty = arg2.is_none_or(|a| a.is_empty());
    let mut cidr2 = SfCidr::new();
    if !cidr2_empty {
        cidr2.set_str(arg2.unwrap());
    }
    let ip1 = cidr1.get_addr();
    let ip2 = cidr2.get_addr();

    match func {
        "sfip_pton" => {
            let buf = ip1.ntop(true).unwrap_or_default();
            // C: result = strcmp(buf,arg2) ? SFIP_FAILURE(1) : SFIP_SUCCESS(0)
            if arg2.is_some() && buf == arg2.unwrap() {
                (0, SUCCESS)
            } else {
                (1, FAILURE)
            }
        }
        "sfip_contains" => (0, cidr1.contains(Some(ip2))),
        "sfip_is_set" => (if ip1.is_set() { 0 } else { 1 }, FAILURE),
        "sfip_is_loopback" => (if ip1.is_loopback() { 0 } else { 1 }, FAILURE),
        "sfip_ismapped" => (if ip1.is_mapped() { 0 } else { 1 }, FAILURE),
        "sfip_compare" => (0, ip1.compare(ip2, true)),
        "sfip_compare_unset" => (0, ip1.compare(ip2, false)),
        "sfip_fast_eq4" => (if ip1.fast_eq4(ip2) { 0 } else { 1 }, FAILURE),
        "sfip_fast_lt6" => (if ip1.fast_lt6(ip2) { 0 } else { 1 }, FAILURE),
        "sfip_fast_gt6" => (if ip1.fast_gt6(ip2) { 0 } else { 1 }, FAILURE),
        "sfip_fast_eq6" => (if ip1.fast_eq6(ip2) { 0 } else { 1 }, FAILURE),
        "sfip_fast_cont4" => (if cidr1.fast_cont4(ip2) { 0 } else { 1 }, FAILURE),
        "sfip_fast_cont6" => (if cidr1.fast_cont6(ip2) { 0 } else { 1 }, FAILURE),
        "sfip_obfuscate" => {
            let mut ip = SfIp::new();
            if ip1.get_family() as i16 == AF_INET {
                ip.set_str("4.3.2.1");
            } else {
                ip.set_str("8:7:6:5:4:3:2:1");
            }
            ip.obfuscate(&cidr1);
            (0, ip.compare(ip2, true))
        }
        _ => (0, FAILURE),
    }
}

/// FuncCheck: enum-valued funcs (C `result` holds an SfIpRet) vs int boolean ops.
fn func_check(i: usize, f: &FuncTest) -> bool {
    let (bresult, eresult) = run_func(f.func, f.arg1, f.arg2);
    match f.func {
        "sfip_compare" | "sfip_compare_unset" | "sfip_contains" | "sfip_obfuscate" => {
            eresult == f.expected
        }
        _ => {
            // C table stores SFIP_SUCCESS(0)/SFIP_FAILURE(1) as the int result
            let exp_int = match f.expected {
                SUCCESS => 0,
                _ => 1,
            };
            let _ = i;
            bresult == exp_int
        }
    }
}

#[allow(dead_code)]
fn _unused() {}

fn set_check(f: &FuncTest) -> bool {
    let mut ip1 = SfIp::new();
    ip1.set_str(f.arg1);
    let mut ip2 = SfIp::new();
    // mirror set(ip1.get_ptr(), ip1.get_family())
    let status = if ip1.is_ip4() {
        ip2.set_raw(&ip1.ip8[12..16], ip1.family)
    } else {
        ip2.set_raw(&ip1.ip8, ip1.family)
    };
    status == SfIpRet::Success && ip1.ip8 == ip2.ip8 && ip1.family == ip2.family
}

fn copy_check(f: &FuncTest) -> bool {
    let mut ip1 = SfIp::new();
    ip1.set_str(f.arg1);
    let ip2 = ip1; // Rust Copy == C++ struct assignment
    ip1.ip8 == ip2.ip8 && ip1.family == ip2.family
}

#[test]
fn sfip_exec() {
    let t = ftests();
    let mut failures = Vec::new();
    for (i, f) in t.iter().enumerate() {
        if !func_check(i, f) {
            failures.push(format!(
                "[{}] {}({:?}, {:?}) expected {:?}",
                i, f.func, f.arg1, f.arg2, f.expected
            ));
        }
    }
    assert!(failures.is_empty(), "sfip exec failures:\n{}", failures.join("\n"));
}

#[test]
fn sfip_set() {
    let t = ftests();
    for f in t.iter() {
        assert!(set_check(f), "sfip set: {}({:?})", f.func, f.arg1);
    }
}

#[test]
fn sfip_copy() {
    let t = ftests();
    for f in t.iter() {
        assert!(copy_check(f), "sfip copy: {}({:?})", f.func, f.arg1);
    }
}

#[test]
fn uri_parsing() {
    let mut ip = SfIp::new();
    assert!(!parse_ip_from_uri("", &mut ip));
    assert!(!parse_ip_from_uri("1111:2222:3333:4444:5555:6666:7777:8888:9999", &mut ip));
    assert!(!parse_ip_from_uri("http://", &mut ip));
    assert!(parse_ip_from_uri("http://1.2.3.4:80", &mut ip));
    assert!(parse_ip_from_uri("https://1.2.3.5/about.html", &mut ip));
    assert!(parse_ip_from_uri("[1111::2222]/about.html", &mut ip));
}
