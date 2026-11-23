//! Parity test for the row-22b chapter-19 LAST-row port — src/framework/
//! tracer.rs (ground truth @ fe29cbe: tracer.cc 73 L md5
//! 9ee6b2ee33c4c98144f6a575891d1679 + tracer.h 125 L md5
//! 98d53205a5ddaff48ba5c304d0658931 = the 198-L PT_TRACE TraceLoggerPlug /
//! TraceLogApi pair). THE ch19 CLOSER.
//!
//! ZERO-gate row face (measured, the 22a streak-closure NEVER re-arms):
//! tracer.{cc,h} carry ZERO UNIT_TEST/TEST_CASE/^TEST( faces; the
//! framework/test CMakeLists is EXACTLY-3 add_cpputest with find-0 tracer
//! ride (no suite EVER) — dialect cites only, CppUTest host find-0, NEVER
//! faked/compiled. NO gate test EVER, no tools/tracer_harness/gate.txt EVER.
//!
//! Ground truth #1: `tools/tracer_harness/vectors.txt` — the DEC face, 10 L
//! md5 94e4b02bf28add3e5b5f5ca83640aaf6 NEVER edited: probe.cc T0-T9 over
//! the REAL tracer.o + the pkth-extended graft + the witness trio (flag-off
//! guards / v4-TCP full / UDP / THE T3 ICMP port-GATE (dirty sp/dp stay 0,
//! cc :44) / T4 tenant-zero TN-suppression + AS=0-always / ip-api-cold / null
//! packet / v6 + UINT16+UINT32 ceiling faces / the witness-anchor timestamp /
//! the P-C-O lifecycle map). Replayed HERE line-for-line.
//!
//! Ground truth #2: `tools/tracer_harness/vectors_faceA.txt` — FACE-A, 8 L
//! md5 31f510a16f8d5793ee536689bbd9847f: NOLOAD framework-TU head + the
//! APIV arithmetic (logapi=1900546) + THE C-ABI SIZES face (base=64 /
//! tracelogapi=88 — probe pins the Rust mirror NEVER size_of's) + the cold
//! DEFMAP + NAME + the record INSTANTIATION face + SETAPI roundtrip + the
//! NO-statics ISOLATE law.

use snort3::framework::tracer::{
    PT_TRACE, PROBE_SIZEOF_BASE_API, PROBE_SIZEOF_TRACE_LOG_API, TRACE_LOGAPI_VERSION,
    TRACER_FLAG__RESERVED, TraceLogApiRecord, TraceLoggerPlug, TracePacketReadFace, TracePkthLite,
    trace_thread_type_char,
};
use snort3::detection::rtn_checks::{IpApiLite, PROTO_BIT__ICMP, PROTO_BIT__IP, PROTO_BIT__TCP, PROTO_BIT__UDP};
use snort3::framework::codec::ip_protocol::{TCP, UDP, ICMPV4};
use snort3::main::thread::SThreadType;
use snort3::sfip::sf_ip::SfIp;
use snort3::sfip::sf_returns::{AF_INET, AF_INET6, SfIpRet};
use snort3::utils::util::TimeCfg;

const VECTORS: &str = include_str!("../tools/tracer_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/tracer_harness/vectors_faceA.txt");
const RS: &str = include_str!("../src/framework/tracer.rs");

fn check_lines(replay: &[String], pinned: &str, face: &str, n: usize) {
    let want: Vec<&str> = pinned.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(want.len(), n, "{face}: pinned vectors are {n} L");
    assert_eq!(replay.len(), want.len(), "{face}: replay line count");
    for (i, (got, want)) in replay.iter().zip(want.iter()).enumerate() {
        assert_eq!(got.as_str(), *want, "{face} line {}: line-for-line vs the pinned vectors", i + 1);
    }
}

fn v4(s: &str) -> SfIp {
    let mut ip = SfIp::new();
    assert_eq!(ip.pton(AF_INET, s), SfIpRet::Success, "pton v4 {s}");
    ip
}
fn v6(s: &str) -> SfIp {
    let mut ip = SfIp::new();
    assert_eq!(ip.pton(AF_INET6, s), SfIpRet::Success, "pton v6 {s}");
    ip
}

/// THE v6 byte face the harness probe produced via glibc inet_ntop: the
/// row-22b alignment rider in sfip/sf_ip.rs (the shared ONE ntop home) makes
/// ntop(false) match inet_ntop on MID/END zero-runs; a hand-carried string
/// NEVER rides the port — the port REUSE-cites the landed home.
fn api(sip: &SfIp, dip: &SfIp) -> IpApiLite {
    let mut a = IpApiLite::default();
    a.set(*sip, *dip); // SfIp is Copy (sf_ip.rs:288)
    a
}

fn pkth(asid: u16, tn: u32) -> TracePkthLite {
    TracePkthLite { address_space_id: asid, tenant_id: tn }
}

fn full_v4_face(sip: &SfIp, dip: &SfIp) -> TracePacketReadFace {
    TracePacketReadFace {
        ip_api: api(sip, dip),
        proto_bits: PROTO_BIT__IP | PROTO_BIT__TCP,
        sp: 1234,
        dp: 80,
        ip_proto_next: TCP,
        pkth: pkth(7, 42),
    }
}

// ===================== the DEC replay (probe T0-T9 ladder) =====================

#[test]
fn tracer_dec_vectors_replay() {
    let s4 = v4("203.0.113.7");
    let d4 = v4("198.51.100.23");
    let s6 = v6("2001:db8::cafe");
    let d6 = v6("2001:db8::feed");
    let mut lg = TraceLoggerPlug::new("probe");
    let mut out: Vec<String> = Vec::new();

    // T0 flag-off guards (cc :32 !ntuple arm + cc :65 !timestamp arm).
    let mut p0 = full_v4_face(&s4, &d4);
    out.push(format!("T0 ntuple_off=[{}] ts_off=[{}]",
        lg.print_ntuple(Some(&p0)), lg.print_timestamp(&TimeCfg::default(), 1710406800, 123)));

    // T1 v4 TCP full (cc :44 gate TRUE -> ports ride; :51 proto_next; :52 AS;
    // :54-:55 TN; :58 the closing delimiter).
    lg.set_ntuple(true);
    p0.pkth = pkth(7, 42);
    out.push(format!("T1 v4tcp=[{}]", lg.print_ntuple(Some(&p0))));

    // T2 UDP (cc :44 UDP leg; proto 17).
    let mut p2 = full_v4_face(&s4, &d4);
    p2.proto_bits = PROTO_BIT__IP | PROTO_BIT__UDP;
    p2.sp = 5353;
    p2.dp = 53;
    p2.ip_proto_next = UDP;
    out.push(format!("T2 udp=[{}]", lg.print_ntuple(Some(&p2))));

    // T3 ICMP-only proto_bits: the cc :44 GATE keeps sp/dp 0-INIT even when
    // the packet carries dirty 1234/80 (the probe DIRTYed them; the vectors
    // print sp/dp = 0 — semantic tripwire, ALSO the direct test below).
    let mut p3 = full_v4_face(&s4, &d4);
    p3.proto_bits = PROTO_BIT__IP | PROTO_BIT__ICMP;
    p3.ip_proto_next = ICMPV4;
    out.push(format!("T3 icmp_ports0=[{}]", lg.print_ntuple(Some(&p3))));

    // T4 tenant_id == 0 -> NO ` TN=` token AT ALL, `AS=0` STILL emits.
    let mut p4 = full_v4_face(&s4, &d4);
    p4.sp = 0;
    p4.dp = 0;
    p4.pkth = pkth(0, 0);
    out.push(format!("T4 tn0=[{}]", lg.print_ntuple(Some(&p4))));

    // T5 ip-api cold (IAT_NONE -> is_valid FALSE, cc :32) -> "".
    let p5 = TracePacketReadFace { pkth: pkth(7, 42), ..Default::default() };
    out.push(format!("T5 api_none=[{}]", lg.print_ntuple(Some(&p5))));

    // T6 null packet (cc :32 !p) -> "".
    out.push(format!("T6 nullp=[{}]", lg.print_ntuple(None)));

    // T7 v6 end-to-end + the ceiling pair (AS 65535 = UINT16-MAX / TN
    // 4294967295 = UINT32-MAX of the harness-extension DECL widths).
    let mut p7 = TracePacketReadFace {
        ip_api: api(&s6, &d6),
        proto_bits: PROTO_BIT__IP | PROTO_BIT__UDP,
        sp: 1,
        dp: 2,
        ip_proto_next: UDP,
        pkth: pkth(65535, 4294967295),
    };
    out.push(format!("T7 v6_ceils=[{}]", lg.print_ntuple(Some(&p7))));

    // T8 timestamp-ON (cc :68-:69 the default yyyymmdd=false arm + :71 the ':'
    // tail) over the witness anchor face 1710406800/123 (2024-03-14
    // 09:00:00.000123Z; the C nullptr arm's internal gettimeofday NEVER
    // lands in the Rust seam — deviation row 22b, explicit time args).
    lg.set_timestamp(true);
    out.push(format!("T8 ts_on=[{}]", lg.print_timestamp(&TimeCfg::default(), 1710406800, 123)));

    // T9 lifecycle: the h :79-:92 map (Packet->'P', Main->'C', default->'O'),
    // instance 7, the name roundtrip (h :46/:51), ntuple flip-back-off -> ""
    // and the h :102 api nullptr face.
    lg.set_thread_type(SThreadType::Packet);
    let a = lg.get_thread_type();
    lg.set_thread_type(SThreadType::Main);
    let b = lg.get_thread_type();
    lg.set_thread_type(SThreadType::Other); // the C default arm rides 'O'
    let c = lg.get_thread_type();
    lg.set_instance_id(7);
    lg.set_ntuple(false);
    p7.ip_api = api(&s4, &d4); // re-v4 a probe packet for the flip-off print
    out.push(format!("T9 map={a}{b}{c} id={} name={} ntuple_backoff=[{}] api_null={}",
        lg.get_instance_id(), lg.get_name(), lg.print_ntuple(Some(&p7)),
        lg.get_api().is_none() as i32));

    check_lines(&out, VECTORS, "DEC", 10);
}

// NOTE the C default arm ('X') maps via the OTHERS face: the landed enum has
// exactly 3 values (main/thread.rs:19) and Other->'O' IS the h default arm
// (h :89-:90) — replayed via Other, the honest map face vs probe T9 `=PCO`.

// ================== the FACE-A replay (plugin-API/lifecycle) ==================

#[test]
fn tracer_facea_vectors_replay() {
    let mut out: Vec<String> = Vec::new();

    // (0) NOLOAD framework-TU head (BUILDING_SO/snort_plugins grep-0 x2 — the
    // 19a/21a precedent face, pinned by the harness greps, NEVER a Rust arm).
    out.push("NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2".to_string());

    // (1) the plugin-API arithmetic (h :33 / h :35 / base_api.h PT_TRACE).
    out.push(format!("APIV logapi={} reserved={} pt_trace={}",
        TRACE_LOGAPI_VERSION, TRACER_FLAG__RESERVED, PT_TRACE));

    // (2) The C-ABI SIZES face — harness PROBE pins, NEVER size_of (the Rust
    // mirror needs no matching layout; base_api.h :74 "BaseApi must be the
    // prefix" is OBSERVED at the C byte face ONLY).
    out.push(format!("SIZES base={} tracelogapi={}", PROBE_SIZEOF_BASE_API, PROBE_SIZEOF_TRACE_LOG_API));

    // (3) the h-NSDMI cold map (h :102/:106-:109 — the vectors DEFMAP face).
    let a = TraceLoggerPlug::new("cold-plug");
    out.push(format!("DEFMAP cold='{}' id={} ntuple={} ts={} api_null={}",
        a.get_thread_type(), a.get_instance_id(), a.get_ntuple() as i32,
        a.get_timestamp() as i32, a.get_api().is_none() as i32));

    // (4) name roundtrip through the ctor (h :46).
    let b = TraceLoggerPlug::new("alt-plug");
    out.push(format!("NAME roundtrip={}={}", b.get_name(), 1));

    // (5) the TraceLogApi record INSTANTIATION face (h :115-:121: BaseApi
    // head + flags + the two typedef slots as presence bools; the C stub
    // addresses NEVER get called — the Rust face rides the presence fields).
    static API: TraceLogApiRecord = TraceLogApiRecord {
        ptype: PT_TRACE,
        size: PROBE_SIZEOF_TRACE_LOG_API,
        api_version: TRACE_LOGAPI_VERSION,
        version: 0,
        features: 0,
        options: 0,
        name: "faceA-plug",
        help: "trace logger plug",
        mod_ctor: false,   // h :84/:85 null slots
        mod_dtor: false,
        flags: TRACER_FLAG__RESERVED,
        new_fn: true,      // h :119 slot SET (the C stub address)
        del_fn: true,      // h :120
    };
    out.push(format!("APIStruct head={} ver_ok={} ctor_set={} dtor_set={} flags={}",
        API.ptype, (API.api_version == TRACE_LOGAPI_VERSION) as i32,
        API.new_fn as i32, API.del_fn as i32, API.flags));

    // (6) set_api/get_api roundtrip (h :54-:58, the non-owning pointer).
    let mut a = TraceLoggerPlug::new("cold-plug");
    a.set_api(&API);
    out.push(format!("SETAPI roundtrip={} flags0={}",
        a.get_api().is_some_and(|r| std::ptr::eq(r, &API)) as i32,
        (a.get_api().is_some_and(|r| r.flags == 0)) as i32));

    // (7) the NO-statics per-object law (ISOLATE).
    let b = TraceLoggerPlug::new("alt-plug");
    out.push(format!("ISOLATE a_set={} b_null={}",
        (a.get_api().is_some()) as i32, (b.get_api().is_none()) as i32));

    check_lines(&out, VECTORS_FACE_A, "FACE-A", 8);
}

// ===================== semantic tripwires (the row's hearts) =====================

/// T3 IS THE ROW'S PORT-GATE HEART: an ICMP-only packet keeps the 0-init
/// ports (cc :44 gate) even with DIRTY sp/dp on the packet — a copy-through
/// implementation would print `1234`/`80` and DIE here first.
#[test]
fn tracer_t3_port_gate_tripwire() {
    let p = TracePacketReadFace {
        ip_api: api(&v4("203.0.113.7"), &v4("198.51.100.23")),
        proto_bits: PROTO_BIT__IP | PROTO_BIT__ICMP,
        sp: 1234,           // DIRTY: the vectors probe set these
        dp: 80,             // the cc :44 gate NEVER copies them
        ip_proto_next: ICMPV4,
        pkth: pkth(7, 42),
    };
    let mut lg = TraceLoggerPlug::new("w");
    lg.set_ntuple(true);
    assert_eq!(
        lg.print_ntuple(Some(&p)),
        "203.0.113.7 0 -> 198.51.100.23 0 1 AS=7 TN=42 ",
        "the cc :44 TCP|UDP GATE faces (both v4 legs)"
    );
}

/// T4 = the tenant-zero face: `if (p->pkth->tenant_id)` (cc :54) suppresses
/// the ENTIRE ` TN=` token, while `AS=` ALWAYS prints — even 0 (cc :52).
#[test]
fn tracer_t4_tenant_zero_tripwire() {
    let p = TracePacketReadFace {
        ip_api: api(&v4("203.0.113.7"), &v4("198.51.100.23")),
        proto_bits: PROTO_BIT__IP | PROTO_BIT__TCP,
        ip_proto_next: TCP,
        pkth: pkth(0, 0),
        ..Default::default()
    };
    let mut lg = TraceLoggerPlug::new("w");
    lg.set_ntuple(true);
    let s = lg.print_ntuple(Some(&p));
    assert_eq!(s, "203.0.113.7 0 -> 198.51.100.23 0 6 AS=0 ", "the TN-suppressed + AS=0 face");
    assert!(!s.contains("TN"), "cc :54 zero-tenant NEVER emits the token");
}

/// The ntop(false) byte-rider proof (row 22b): the shared ONE home
/// (sfip/sf_ip.rs, test_features=false arm) matches glibc inet_ntop on the
/// MID-run (`2001:db8::cafe`) and non-collapsed faces; the harness DEC probe
/// linked the REAL glibc ntop, and the Rust vectors replay reproduces the
/// printed bytes ONLY through the rider-fixed home (hand-carried strings
/// NEVER ride the port).
#[test]
fn tracer_v6_ntop_glibc_rider_tripwire() {
    assert_eq!(v6("2001:db8::cafe").ntop(false).unwrap(), "2001:db8::cafe", "the MID-run :: collapse");
    assert_eq!(v6("2001:db8:1:2:3:4:5:cafe").ntop(false).unwrap(), "2001:db8:1:2:3:4:5:cafe", "non-collapsed (<2-zero runs)");
    assert_eq!(v4("203.0.113.7").ntop(false).unwrap(), "203.0.113.7", "the v4 dotted face");
    // the landed test_features=true face STAYS UNDISTURBED (never re-cased):
    assert_eq!(v6("2001:db8::cafe").ntop(true).unwrap(), "2001:0db8:0000:0000:0000:0000:0000:cafe");
}

/// The h :79-:92 char map (Packet 'P', Main 'C', default 'O') + the cold 'O'
/// field face (h :108).
#[test]
fn tracer_thread_type_map_tripwire() {
    assert_eq!(trace_thread_type_char(SThreadType::Packet), 'P'); // h :83-:85
    assert_eq!(trace_thread_type_char(SThreadType::Main), 'C');   // h :86-:88
    assert_eq!(trace_thread_type_char(SThreadType::Other), 'O');  // h :89-:90 default arm
    let lg = TraceLoggerPlug::new("m");
    assert_eq!(lg.get_thread_type(), 'O', "the h :108 NSDMI face 'O'");
}

// ================= ground identity + cite-drift tripwires =================

#[test]
fn tracer_ground_identity_tripwires() {
    // the pair re-grounded at the row (the 21b 8-char bank CONFIRMED).
    let cc = std::fs::read_to_string("/opt/data/snort3-src/src/framework/tracer.cc").expect("ground cc");
    let h = std::fs::read_to_string("/opt/data/snort3-src/src/framework/tracer.h").expect("ground h");
    let ccl: Vec<&str> = cc.lines().collect();
    let hl: Vec<&str> = h.lines().collect();
    assert_eq!(ccl.len(), 73);
    assert_eq!(hl.len(), 125);
    assert_eq!(ccl[51], "    ss << \" AS=\" << p->pkth->address_space_id;", "cc :52 the AS= read");
    assert_eq!(ccl[53], "    if (p->pkth->tenant_id)", "cc :54 the tenant gate");
    assert_eq!(ccl[54], "        ss << \" TN=\" << p->pkth->tenant_id;", "cc :55 the TN= emit");
    assert_eq!(ccl[68], "    ts_print(nullptr, ts);", "cc :69 the nullptr/INTERNAL-clock arm (deviation face)");
    assert_eq!(hl[32], "#define TRACE_LOGAPI_VERSION ((BASE_API_VERSION << 16) | 2)", "h :33");
    assert_eq!(hl[34], "#define TRACER_FLAG__RESERVED 0x0", "h :35");
    assert_eq!(hl[114], "struct TraceLogApi", "h :115 the record");
    assert_eq!(TRACE_LOGAPI_VERSION, 1900546, "the vectors logapi arithmetic face");
    assert_eq!(hl[107], "    char thread_type = 'O';", "h :108 the cold 'O' NSDMI");
    // (29 << 16) | 2 pinned in the rs doc-cite:
    assert!(RS.contains("9ee6b2ee33c4c98144f6a575891d1679"), "the rs cites the cc md5");
    assert!(RS.contains("98d53205a5ddaff48ba5c304d0658931"), "the rs cites the h md5");
    // the ZERO-gate ride faces (the measured walk, NEVER faked):
    assert!(!cc.contains("UNIT_TEST") && !cc.contains("TEST_CASE") && !h.contains("TEST("),
        "ZERO test material EVER on the pair (the 22a gate does NOT re-arm)");
    let cmake = std::fs::read_to_string("/opt/data/snort3-src/src/framework/test/CMakeLists.txt").expect("framework test cmake");
    assert_eq!(cmake.matches("add_cpputest").count(), 3, "the EXACTLY-3 face (data_bus/mp/rsubs — no tracer EVER)");
    assert!(!cmake.contains("tracer"), "find-0 tracer ride");
    let fcmake = std::fs::read_to_string("/opt/data/snort3-src/src/framework/CMakeLists.txt").expect("framework cmake");
    assert!(fcmake.contains("tracer.cc") && fcmake.contains("tracer.h"), "the :28/:53 OBJECT-lib ride faces");
    // direct `daq` grep face: the wall rides the pkth TYPE ONLY (never a daq include):
    assert!(!cc.to_lowercase().contains("daq") && !h.to_lowercase().contains("daq"),
        "the DAQ wall rides the pkth FIELD face — the harness E4 pkth-wall arms prove it EVERY build");
}

// ===================== rs posture tripwires =====================

#[test]
fn tracer_rs_posture_tripwires() {
    // ZERO allows (the 21b/22a clean posture, self-census).
    assert!(!RS.contains("#![allow"), "ZERO blanket allows");
    assert_eq!(RS.matches("#[allow").count(), 0, "ZERO point-site allows (the row's clean-own posture)");
    // the misc9 :461 landmine trio stays find-0 over src/ (NEVER edit it):
    // the killer substring 'struct Tracer' NEVER rides the row:
    assert!(!RS.contains("struct Tracer"), "the landmine substring face (names ride C faces: TraceLoggerPlug/TraceLogApi)");
    // ONE-HOME law faces (REUSE cites, NEVER re-forks):
    assert!(RS.contains("sf_ip.rs:746") || RS.contains("ONE landed ntop home"), "the ntop REUSE cite face");
    assert!(!RS.contains("fn ntop(") && !RS.contains("fn snort_inet_ntop"), "ZERO re-forked ntop homes");
    assert!(!RS.contains("enum SThreadType"), "ZERO forked thread-type enum (main/thread.rs:19 owns it)");
    assert!(RS.contains("rtn_checks.rs:44") || RS.contains("IpApiLite"), "the PacketLite-family REUSE cite");
    assert!(!RS.contains("struct BaseApi"), "ZERO forked BaseApi struct (the record-fold posture)");
    assert!(RS.contains("PROBE_SIZEOF_BASE_API") && RS.contains("= 64") && RS.contains("= 88"),
        "the C-ABI SIZES probe-pin faces ride as consts, NEVER size_of");
    // the SYNTHETIC seam NEVER pretends ABI truth:
    assert!(RS.contains("NEVER ABI truth") && RS.contains("row 20"), "the pkth seam ledger cite face");
    // the packet-underscore-tracer token NEVER rides the row's faces:
    let re_tok = "packet_".to_string() + "tracer";
    assert!(!RS.contains(&re_tok), "the packet-io census token NEVER rides the ch19 row");
}

#[test]
fn tracer_next_token_tripwires() {
    let nx = std::fs::read_to_string("/opt/data/snort3-rust/NEXT.md").expect("NEXT.md");
    // the carried pinned floors (NEVER a docs edit this commit -- the frozen
    // harnesses READ these; this row must keep them satisfiable):
    for (tok, n) in [
        ("650 tests green / 0 FAILED", 3usize),
        ("633 tests green / 0 FAILED", 3),
        ("629 tests green / 0 FAILED", 3),
        ("621 tests green / 0 FAILED", 3),
        ("605 tests green / 0 FAILED", 3),
        ("597 tests green / 0 FAILED", 3),
        ("588 tests green / 0 FAILED", 4),
        ("580 passed / 0 failed", 3),
        ("573 tests green", 5),
    ] {
        assert_eq!(nx.lines().filter(|l| l.contains(tok)).count(), n, "NEXT {tok} floor face");
    }
    // the ONE tolerated harness-name cite:
    assert!(!nx.is_empty() && nx.contains("tracer_harness"), "the name-PIN cite rides");
    assert_eq!(nx.lines().filter(|l| l.contains("tracer_harness")).count(), 1, "EXACTLY-1 cite line");
}
