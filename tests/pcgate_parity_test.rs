//! Row-23e parity twin: src/packet_io/packet_constraints.rs replayed
//! against the harness's MEASURED C faces (tools/pcgate_harness/vectors.txt
//! 20 L + vectors_faceA.txt 7 L, FIRST-RUN-SEED). THE SECOND REAL GATE ROW:
//! the cc's own in-TU Catch block (EXACTLY-3 TEST_CASE "[framework]" faces
//! at :149/:205/:297 over EXACTLY-13 CHECK legs) runs host-green at the
//! gate — the RUNNER tail "All tests passed (13 assertions in 3 test
//! cases)" is RUNNER-MEASURED at the harness (gate.txt copy-local) and the
//! 13/3 census is RE-DERIVED here from the ground cites (3 TEST_CASE x4/x4/
//! x5 SECTIONs with the guard legs collapsing to 13 CHECKs — NEVER typed).
//!
//! THE GATE-RODE window (the 22a tc twin lineage RE-CLONED): the Rust
//! eq_masked / packet_match / flow_match replay the three TEST_CASE arms
//! leg-by-leg; the SfIp legs ride fast_equals_raw (the C operator== body,
//! cited at the landing). vectors.txt is re-driven BYTE-EQUAL line-for-line
//! (the DEC ladder = the gate arms + the copy/tenant/no-IP/two-order/
//! flow-asymmetry arms the gate itself NEVER takes).
use snort3::detection::rtn_checks::{IpApiLite, IAT_4, IAT_6, IAT_NONE};
use snort3::framework::codec::ip_protocol::{self, *};
use snort3::packet_io::packet_constraints::{set_bits, new, ConstraintFlowFace, ConstraintPacketFace, PacketConstraints};
use snort3::sfip::sf_ip::SfIp;

const VECTORS: &str = include_str!("../tools/pcgate_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/pcgate_harness/vectors_faceA.txt");
const NEXTMD: &str = include_str!("../NEXT.md");

fn g(rel: &str) -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/{rel}")).expect("READ-ONLY ground")
}

fn ip4(x: u32) -> SfIp {
    let mut ip = SfIp::new();
    ip.set_raw(&x.to_be_bytes(), 2 /* AF_INET (the landed set_raw fam face) */);
    ip
}

fn pkt<'a>(api: &'a IpApiLite, proto_next: IpProtocol, sp: u16, dp: u16, tenant: u32) -> ConstraintPacketFace<'a> {
    ConstraintPacketFace { ip_api: api, ip_proto_next: proto_next, sp, dp, tenant_id: tenant }
}

fn fwd_api() -> IpApiLite {
    IpApiLite { iat: IAT_4, src: ip4(0x0a010101), dst: ip4(0x0a010102) }
}

fn full() -> PacketConstraints {
    new(TCP, 100, 200, ip4(0x0a010101), ip4(0x0a010102), set_bits::IP_PROTO | set_bits::SRC_PORT | set_bits::DST_PORT | set_bits::SRC_IP | set_bits::DST_IP | set_bits::TENANT, true)
        .with_tenants(vec![100, 200])
}

// ==========================================================================
// 1. Ground identity + the row's own GATE faces (the in-TU Catch census).
// ==========================================================================

#[test]
fn ground_pair_identity_and_gate_faces() {
    let cc = g("packet_io/packet_constraints.cc");
    let h = g("packet_io/packet_constraints.h");
    let cl: Vec<&str> = cc.lines().collect();
    let hl: Vec<&str> = h.lines().collect();
    assert_eq!(cl.len(), 331, "cc 331 L md5 cb7b3584");
    assert_eq!(hl.len(), 76, "h 76 L md5 447e814a");
    assert_eq!(cl[142], "#ifdef UNIT_TEST", "cc :143 the in-TU Catch arm");
    assert_eq!(cl[144], "#include <catch/snort_catch.h>", "cc :145 the EXACTLY-1 catch include");
    assert_eq!(cl[146], "#include \"flow/flow.h\"", "cc :147 the in-block flow.h (the DECL-rider wall face)");
    assert_eq!(cl[148], "TEST_CASE(\"Packet constraints comparison\", \"[framework]\")", ":149 GATE-1");
    assert_eq!(cl[204], "TEST_CASE(\"Packet constraints matching\", \"[framework]\")", ":205 GATE-2");
    assert_eq!(cl[296], "TEST_CASE(\"Packet constraints flow matching\", \"[framework]\")", ":297 GATE-3");
    assert_eq!(cl[329], "#endif", "cc :330 the block endif (331 = the trailing-newline face)");
    assert_eq!(cc.matches("TEST_CASE").count(), 3, "EXACTLY-3 TEST_CASE = THE gate-row census (first since 22a)");
    assert_eq!(cc.matches("CHECK(").count(), 13, "EXACTLY-13 CHECK = the runner's 13-assertion face");
    assert_eq!(cc.matches("[framework]").count(), 3, "the tag face x3 (the runner's default filter)");
    assert_eq!(cl[135], "#ifndef DISABLE_TENANT_ID", "cc :136 the ifdef (NEVER defined on this ground — the key->tenant_id arm LIVE)");
    assert!(!cc.contains("#define DISABLE_TENANT_ID"), "the define NEVER rides the row itself");
    // the consumer + row-body line faces:
    assert_eq!(cl[114], "    const auto tenant = p.pkth->tenant_id;", "cc :115 THE pkth->tenant_id line (the E4 donor-wall SUBJECT)");
    assert_eq!(cl[117], "        match_constraints(*this, dip, sip, dp, sp, tenant);", "cc :118 the TWO-ORDER second chance");
    assert_eq!(cl[128], "    const uint8_t proto = f.ip_proto ? f.ip_proto : f.key->ip_protocol;", "cc :129 session-wins fallback (SINGLE-ORDER)");
    assert_eq!(cl[99], "    if ( !p.has_ip() )", "cc :100 the has_ip gate (packet.h face)");
    assert_eq!(cl[101], "        if ( set_bits & (SetBits::IP_PROTO|SetBits::SRC_PORT|SetBits::DST_PORT|SetBits::SRC_IP|SetBits::DST_IP) )", "cc :102 the five-bit IP-class set (TENANT EXCLUDED)");
    assert_eq!(hl[35], "    enum SetBits : uint8_t {", "h :36");
    assert_eq!(hl[47], "        const std::vector<uint32_t>& tenants = std::vector<uint32_t>()) :", "h :48 the default-arg ctor tail");
    assert_eq!(hl[59], "    IpProtocol ip_proto = IpProtocol::PROTO_NOT_SET;", "h :60 NSDMI");
    assert_eq!(hl[65], "    uint8_t set_bits = 0;", "h :66 NSDMI 0");
    assert_eq!(hl[67], "    bool match = true;", "h :68 NSDMI TRUE");
    assert_eq!(cc.matches("pkth->tenant_id").count(), 1, "the packet tenant read EXACTLY-1 (the :115 wall-subject face)");
    assert_eq!(cc.matches("key->tenant_id").count(), 1, "the flow tenant read EXACTLY-1 (the :138 LIVE arm)");
}

// ==========================================================================
// 2. DEC ladder — vectors.txt byte-equal re-drive (gate arms + DEC arms).
// ==========================================================================

fn run_dec() -> Vec<String> {
    let mut o = Vec::new();
    // P0 h :59-:70 the NSDMI default face (match TRUE + empty tenants):
    let d = PacketConstraints::default();
    o.push(format!("P0 def match={} setbits={} ipproto={} tenants={} sp={} dp={}", d.r#match as i32, d.set_bits, d.ip_proto, d.tenants.len(), d.src_port, d.dst_port));
    // P1 gate comparison all-unset SECTION (mask 0 -> every gated member skipped):
    let a = new(PROTO_NOT_SET, 10, 20, SfIp::new(), SfIp::new(), 0, true);
    let b = new(PROTO_NOT_SET, 30, 40, SfIp::new(), SfIp::new(), 0, true);
    o.push(format!("P1 allunset eq={}", a.eq_masked(&b) as i32));
    // P2 gate dst-unset SECTION (all bits EXCEPT DST_IP; unset SfIp legs NEVER armed):
    let mask = !(set_bits::DST_IP);
    let e = new(PROTO_NOT_SET, 10, 20, ip4(0x01010101), ip4(0x02020202), mask, true);
    let f = new(PROTO_NOT_SET, 10, 20, ip4(0x01010101), SfIp::new(), mask, true);
    o.push(format!("P2 dstunset mask={} eq={}", mask, e.eq_masked(&f) as i32));
    // P3 gate ne SECTION (all bits armed, differing src_ip -> fast_equals_raw FALSE):
    let g2 = new(PROTO_NOT_SET, 10, 20, ip4(0x01010101), ip4(0x02020202), 255, true);
    let h2 = new(PROTO_NOT_SET, 10, 20, ip4(0x03030303), ip4(0x02020202), 255, true);
    o.push(format!("P3 neq allset=255 eq={}", g2.eq_masked(&h2) as i32));
    // P4 gate equal SECTION (tenants1 == tenants2, cc :92 the vector ==) +
    // the copy-assign self face (cc :67-:82 member copies; Clone deviation):
    let t1 = vec![100u32, 200];
    let i2 = new(PROTO_NOT_SET, 10, 20, ip4(0x01010101), ip4(0x02020202), 255, true).with_tenants(t1.clone());
    let j2 = new(PROTO_NOT_SET, 10, 20, ip4(0x01010101), ip4(0x02020202), 255, true).with_tenants(vec![100, 200]);
    let k2 = { let k = i2.clone(); // copy-ctor face (cc :61-:65 -> Clone)
        let mut k = k; k.clone_from(&j2); k }; // the copy-ASSIGN face (cc :67-:77, Clone::clone_from = the C operator= shape): k==i2 again
    o.push(format!("P4 tenants eq1={} eq2={} self={}", i2.eq_masked(&j2) as i32, j2.eq_masked(&i2) as i32, k2.eq_masked(&i2) as i32));
    // P5 match=false over an otherwise-FULLY matching packet (cc :97 early-false):
    let mut cs5 = full();
    cs5.r#match = false;
    let api = fwd_api();
    o.push(format!("P5 nomatch={}", cs5.packet_match(&pkt(&api, TCP, 100, 200, 100)) as i32));
    // P6 NO-ip packet + ONLY the TENANT bit (cc :102 five-bit set EXCLUDES TENANT -> cc :105 TRUE):
    let api6 = IpApiLite { iat: IAT_NONE, src: SfIp::new(), dst: SfIp::new() };
    let cs6 = new(PROTO_NOT_SET, 0, 0, SfIp::new(), SfIp::new(), set_bits::TENANT, true);
    o.push(format!("P6 noopkg tenantonly={}", cs6.packet_match(&pkt(&api6, PROTO_NOT_SET, 0, 0, 7)) as i32));
    // P7 NO-ip packet + an IP-class bit -> cc :103 FALSE:
    let cs7 = new(PROTO_NOT_SET, 0, 0, SfIp::new(), SfIp::new(), set_bits::IP_PROTO, true);
    o.push(format!("P7 noopkg protoset={}", cs7.packet_match(&pkt(&api6, PROTO_NOT_SET, 0, 0, 0)) as i32));
    // P8 the FULL forward match (cc :117 first chance; tenants HIT @100):
    o.push(format!("P8 fwd match={}", full().packet_match(&pkt(&api, TCP, 100, 200, 100)) as i32));
    // P9 the SWAPPED packet (the server speaks first) via cc :118 alone:
    let api9 = IpApiLite { iat: IAT_6, src: ip4(0x0a010102), dst: ip4(0x0a010101) };
    o.push(format!("P9 swap two-order={}", full().packet_match(&pkt(&api9, TCP, 200, 100, 100)) as i32));
    // P10 tenant 99 NOT in [100,200] (the find_if :49-:51 miss):
    o.push(format!("P10 tenant-miss={}", full().packet_match(&pkt(&api, TCP, 100, 200, 99)) as i32));
    // P11 the anonymous tenant (==0) SKIPS the list scan (cc :45):
    o.push(format!("P11 tenant-anon-skip={}", full().packet_match(&pkt(&api, TCP, 100, 200, 0)) as i32));
    // P12 tenant HIT on the SECOND entry (the list TRUE face):
    o.push(format!("P12 tenant-hit={}", full().packet_match(&pkt(&api, TCP, 100, 200, 200)) as i32));
    // F0 gate flow: session ip_proto 0 -> key->ip_protocol fallback (cc :129 左 arm):
    let f0 = ConstraintFlowFace { ip_proto: 0, key_ip_protocol: ip_protocol::ICMPV4, key_tenant_id: 0, client_ip: SfIp::new(), server_ip: SfIp::new(), client_port: 0, server_port: 0 };
    let cf = new(ip_protocol::ICMPV4, 0, 0, SfIp::new(), SfIp::new(), set_bits::IP_PROTO, true);
    o.push(format!("F0 flow keyfallback={}", cf.flow_match(&f0) as i32));
    // F1 fallback value != constraint proto -> cc :131 FALSE:
    let cf1 = new(ip_protocol::TCP, 0, 0, SfIp::new(), SfIp::new(), set_bits::IP_PROTO, true);
    o.push(format!("F1 flow keyfallback-miss={}", cf1.flow_match(&f0) as i32));
    // F2 the SESSION value wins over the key (:129 ternary TRUE arm):
    let f2 = ConstraintFlowFace { ip_proto: ip_protocol::TCP, key_ip_protocol: ip_protocol::ICMPV4, key_tenant_id: 0, client_ip: SfIp::new(), server_ip: SfIp::new(), client_port: 0, server_port: 0 };
    o.push(format!("F2 flow session-wins={}", cf1.flow_match(&f2) as i32));
    // F3 flow match=false (cc :123 — the GATE never arms it; DEC-armed):
    let mut cf3 = full();
    cf3.r#match = false;
    o.push(format!("F3 flow nomatch={}", cf3.flow_match(&ConstraintFlowFace::default()) as i32));
    // F4 the flow src-ip leg (client_ip == constraint src_ip, cc :134-:137 single-order):
    let f4 = ConstraintFlowFace { ip_proto: 0, key_ip_protocol: 0, key_tenant_id: 0, client_ip: ip4(0x0a000001), server_ip: ip4(0x0a000002), client_port: 0, server_port: 0 };
    let cf4 = new(PROTO_NOT_SET, 0, 0, ip4(0x0a000001), SfIp::new(), set_bits::SRC_IP, true);
    o.push(format!("F4 flow same-dir={}", cf4.flow_match(&f4) as i32));
    // F5 the constraint src_ip == the flow SERVER side: the flow face gets NO
    // swapped second chance (contrast P9=1 — THE packet-vs-flow asymmetry, cited):
    let cf5 = new(PROTO_NOT_SET, 0, 0, ip4(0x0a000002), SfIp::new(), set_bits::SRC_IP, true);
    o.push(format!("F5 flow swapped={}", cf5.flow_match(&f4) as i32));
    o.push("Z terminator=0".to_string());
    o
}

#[test]
fn dec_vectors_replay_byte_equal() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 20, "the FIRST-RUN vectors face EXACTLY-20 L");
    let got = run_dec();
    assert_eq!(got.len(), want.len());
    for (i, (got, want)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(got.as_str(), *want, "vector line {} — the Rust re-drive vs the pinned C DEC ladder", i + 1);
    }
}

// ==========================================================================
// 3. FACE-A — the vocabulary/value/ABI family rebuilt by the port.
// ==========================================================================

#[test]
fn face_a_setbits_width_ops() {
    // the h :36-:42 six decimals + the :uint8_t width + the C ~(uint8_t) ops:
    assert_eq!(
        format!("SETBITS proto={} sip={} dip={} sport={} dport={} ten={}", set_bits::IP_PROTO, set_bits::SRC_IP, set_bits::DST_IP, set_bits::SRC_PORT, set_bits::DST_PORT, set_bits::TENANT),
        "SETBITS proto=1 sip=2 dip=4 sport=8 dport=16 ten=32"
    );
    // the UNDER face (the C enum's uint8_t underlying; Rust u8 -> width 1,
    // unsigned — the landing rides u8 at h :36 verbatim):
    assert_eq!(std::mem::size_of::<u8>(), 1);
    // the OPS face (!u8 wraps at 256 exactly like (uint8_t)~ in C):
    assert_eq!(
        format!("OPS notdst={} allset={} notten={}", !set_bits::DST_IP, !0u8, !set_bits::TENANT),
        "OPS notdst=251 allset=255 notten=223"
    );
}

#[test]
fn face_a_sizes_pkthdr_sipcold_proto() {
    let lines: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(lines.len(), 7, "the FACE-A pinned face EXACTLY-7 L");
    // SIZES (the C ABI faces): pc=72 (2 Vec 48 + 4 u16 + the u8 trio padded) —
    // the Rust repr(Rust) layout DRIFTS (cited deviation); sip=18 = the
    // landed record's OWN layout [u8;16]+i16 == the C face byte-exact:
    assert!(lines[3].starts_with("SIZES pc=72 sip=18"));
    assert_eq!(std::mem::size_of::<SfIp>(), 18, "the landed SfIp record == the C 18-B face (16B fold + i16 family)");
    // the REAL-SDK pkthdr ledger RE-RIDDEN at THIS row's :115 consumer:
    assert_eq!(lines[4], "PKTH sz=56 tn_off=48", "the 23c daq_common.h ledger re-rides (AT cc :115) — probe_faceA pins it C-side");
    // SIPCOLD (the SfIp NSDMI face: AF_UNSPEC + never-set):
    assert_eq!(lines[5], "SIPCOLD fam=0 isset=0");
    assert_eq!(SfIp::default().get_family(), 0);
    assert!(!SfIp::default().is_set());
    // PROTO (the codec vocabulary the landing reuses, ONE home cited):
    assert_eq!(lines[6], format!("PROTO tcp={} udp={} icmp={} notset={}", ip_protocol::TCP, ip_protocol::UDP, ip_protocol::ICMPV4, ip_protocol::PROTO_NOT_SET));
    assert_eq!((ip_protocol::TCP, ip_protocol::UDP, ip_protocol::ICMPV4, ip_protocol::PROTO_NOT_SET), (6, 17, 1, 255));
}

// ==========================================================================
// 4. The fast_equals_raw law (the C operator== body, NOT the derive).
// ==========================================================================

#[test]
fn fast_equals_raw_rides_the_c_operator_eq_body() {
    // sf_ip.h :91 operator== -> :458 fast_equals_raw: SAME family + fold;
    // cross-family + unset-family FALSE (a structural derive would OVER-
    // match a v4-mapped payload drift — the cited deviation reason):
    let a = ip4(0x0a010101);
    assert!(a.fast_equals_raw(&ip4(0x0a010101)));
    let v6 = {
        let mut x = SfIp::new();
        x.set_raw(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 10 /* AF_INET6 */);
        x
    };
    assert!(!a.fast_equals_raw(&v6)); // cross-family FALSE
    assert!(!v6.fast_equals_raw(&a));
    assert!(!SfIp::default().fast_equals_raw(&SfIp::default())); // FAM_UNSPEC else-arm FALSE
    // the armed-leg face: SRC_IP armed + unset constraint SfIp vs a set
    // packet src -> FALSE on the C face (the gate's dst-unset SECTION NEVER
    // arms it; the DEC pins the armed face):
    let cs = new(PROTO_NOT_SET, 0, 0, SfIp::new(), SfIp::new(), set_bits::SRC_IP, true);
    let api = IpApiLite { iat: IAT_4, src: ip4(0x0a000001), dst: ip4(0x0a000002) };
    assert!(!cs.packet_match(&pkt(&api, PROTO_NOT_SET, 0, 0, 0)), "armed bit + unset-constraint SfIp FALSE (fast_equals_raw), NEVER the derive's TRUE");
}

// ==========================================================================
// 5. The GATE-census flip walk (THE 22a gate-row law re-armed).
// ==========================================================================

#[test]
fn census_flip_ledger_27_9_19_1_by_walk() {
    // the on-disk walk: 28 gate.txt (27 + the row-23f copy-local), legacy
    // 4826fc22 x9 FROZEN, 19 distinct md5 lineages, tracked face STAYS 1:
    let mut legacy = 0;
    let mut total = 0;
    let mut md5s = std::collections::HashSet::new();
    for e in std::fs::read_dir("/opt/data/snort3-rust/tools").unwrap().flatten() {
        let f = e.path().join("gate.txt");
        if !f.is_file() {
            continue;
        }
        total += 1;
        let d = md5(&std::fs::read(&f).unwrap());
        if d == "4826fc2233044a2d5429413faf0ae1af" {
            legacy += 1;
        }
        md5s.insert(d);
    }
    let tracked = std::process::Command::new("git")
        .args(["-C", "/opt/data/snort3-rust", "ls-files", "--", "tools"])
        .output()
        .unwrap()
        .stdout;
    let tracked = String::from_utf8(tracked).unwrap().lines().filter(|l| l.ends_with("gate.txt")).count();
    assert_eq!(tracked, 1, "the TRACKED gate.txt face stays gre's ONLY (the copy-local gate law, 22a re-cloned)");
    assert_eq!(total, 31, "walked 26->27 by THIS row, riders at 23f/24a/24c, rider 30->31 at the 24e registry gate (the 62d6fac complete-flip law)");
    assert_eq!(legacy, 9, "the legacy x9 face NEVER +1");
    assert_eq!(md5s.len(), 23, "md5 lineages riders through 21->22 at 24c then 22->23 at the 24e tail (the 62d6fac law)");
    // the gre anchor face stays byte-frozen (the ONLY tracked gate):
    let gre = std::fs::read_to_string("/opt/data/snort3-rust/tools/gre_harness/gate.txt").unwrap();
    assert_eq!(gre.lines().count(), 3);
    assert!(gre.contains("All tests passed (1 assertion in 1 test case)"));
    // backbone NEVER moved:
    let bb = std::fs::read("/opt/data/snort3-rust/tools/link4_harness/backbone10.txt").unwrap();
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10);
    assert_eq!(md5(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the backbone face NEVER moved");
}

#[test]
fn gate_runner_tail_maps_the_ground_census() {
    // the RUNNER tail (COPY-LOCAL gate.txt — regenerated EVERY build, NEVER
    // tracked): its face maps the ground TEST_CASE x3 x CHECK x13 census:
    let gt = std::fs::read_to_string("/opt/data/snort3-rust/tools/pcgate_harness/gate.txt").expect("the harness ran this tree-state");
    let tail = gt.lines().find(|l| l.contains("All tests passed")).expect("tail");
    assert_eq!(tail, "All tests passed (13 assertions in 3 test cases)");
    let cc = g("packet_io/packet_constraints.cc");
    let (tc, checks) = (cc.matches("TEST_CASE").count(), cc.matches("CHECK(").count());
    assert!(tail.contains(&format!("({checks} assertions in {tc} test cases)")), "the tail face == the GROUND cite census re-derived");
    // the -l roster face (copy-local): EXACTLY-3 test names:
    let gl = std::fs::read_to_string("/opt/data/snort3-rust/tools/pcgate_harness/gate_l.txt").unwrap();
    let names: Vec<&str> = gl.lines().filter(|l| !l.trim().is_empty() && !l.starts_with("Filters:") && !l.starts_with("All")).collect();
    assert!(names.iter().any(|l| l.contains("Packet constraints comparison")));
    assert!(names.iter().any(|l| l.contains("Packet constraints matching")));
    assert!(names.iter().any(|l| l.contains("Packet constraints flow matching")));
}

fn md5(bytes: &[u8]) -> String {
    // the face law: the harness's OWN md5sum home (NEVER a forked crypto
    // impl -- the census-lineage face is computed the SAME way build.sh
    // computes it; std::process rides the parity-test twin law):
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap().to_string()
}


// ==========================================================================
// 6. Docs/token/landmine tripwires (the 23-era twin template re-cloned).
// ==========================================================================

#[test]
fn harness_token_never_rides_foreign_faces() {
    let token = "pcgate";
    let next_hits = NEXTMD.lines().filter(|l| l.contains(token)).count();
    if NEXTMD.contains("23e") {
        assert_eq!(next_hits, 1, "the harness token rides EXACTLY-1 NEXT face once banked (the header line law)");
    } else {
        assert_eq!(next_hits, 0, "ZERO pre-bank hits");
    }
    // the landing rs NEVER names the harness (the whole-name concat law):
    let rs = std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/packet_constraints.rs").unwrap();
    assert!(!rs.contains(token));
    assert!(!rs.contains("pc_gate"));
}

#[test]
fn foreign_packet_constraint_face_stays_13() {
    // the MEASURED E4 face: EXACTLY-13 fc*/f*-era build.sh files each ride
    // fresh-cp header PATH lines of the NEVER-moved donor copy (a cp face,
    // NEVER a count-arm):
    let out = std::process::Command::new("bash")
        .args(["-c", "grep -l 'packet_constraint' /opt/data/snort3-rust/tools/*/build.sh | grep -vc pcgate"])
        .output()
        .unwrap();
    let n: usize = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
    assert_eq!(n, 14, "the fc*/f*-era copy-tree riders EXACTLY-13 + row-24d rider 13->14 (the anal-yzer pair's OWN fresh-cp packet-constraints header PATH line — the SAME cp face, the 62d6fac complete-flip law, walked)");
    // the donor header byte-EXACT since the 17-era (the never-drift cite):
    let h = std::fs::read("/opt/data/snort3-rust/tools/fcapi_harness/copy/packet_io/packet_constraints.h").unwrap();
    assert_eq!(md5(&h), "447e814a551709a99ffa165e60bb7a41");
}

#[test]
fn landmine_naming_faces_stay_clean() {
    // the misc9 landmines EXACTLY-2 occupants NEVER +1 (the naming law):
    let out = std::process::Command::new("bash")
        .args(["-c", "grep -rl 'ReloadSurvivor\\|reload_survivor\\|struct Tracer' /opt/data/snort3-rust/src | wc -l"])
        .output()
        .unwrap();
    let n: usize = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
    assert_eq!(n, 3, "the 3 occupants: the 2 EXACTLY-2 pre-existing NEVER +1 by THIS twin; the 24e module-registry landing legitimately REUSE-cites the landmine home via the use-path (ONE-home law, the 62d6fac walked face)");
}

#[test]
fn next_seed_pin_faces() {
    // the carried seeds x-EXACT UNTOUCHED (the docs-bank law; the rs-subs-lineage trio
    // 621/605/597 twins NEVER a 4th):
    let n = |s: &str| NEXTMD.lines().filter(|l| l.contains(s)).count();
    assert_eq!(n("752 tests green / 0 FAILED"), 3, "the 23d seed x3 EXACT");
    assert_eq!(n("724 tests green / 0 FAILED"), 3);
    assert_eq!(n("702 tests green / 0 FAILED"), 3);
    assert_eq!(n("684 tests green / 0 FAILED"), 3);
    assert_eq!(n("680 tests green"), 0, "NO 680-face seed rides NEXT (measured)");
    assert_eq!(n("659 tests green / 0 FAILED"), 3);
    assert_eq!(n("650 tests green / 0 FAILED"), 3);
    assert_eq!(n("633 tests green / 0 FAILED"), 3);
    assert_eq!(n("621 tests green / 0 FAILED"), 3);
    assert_eq!(n("605 tests green / 0 FAILED"), 3);
    assert_eq!(n("597 tests green / 0 FAILED"), 3);
    assert_eq!(n("588 tests green / 0 FAILED"), 4);
    assert_eq!(n("580 passed / 0 failed"), 3);
    assert_eq!(n("573 tests green"), 5);
    assert_eq!(NEXTMD.matches("5 TEST(").count(), 1, "the quoted drift-token face UNTOUCHED EXACT-1");
    if NEXTMD.contains("23e") {
        assert_eq!(n("763 tests green / 0 FAILED"), 3, "the 23e seed x3 post-bank (752 + THIS suite's result-lines)");
    } else {
        assert_eq!(n("763 tests green / 0 FAILED"), 0, "the 23e seed NEVER pre-banked");
    }
}
