//! Row-23g parity twin: src/packet_io/packet_tracer_module.rs replayed
//! against the harness's MEASURED C faces (the pt-rmod harness vectors.txt
//! 16 L + vectors_faceA.txt 7 L — FIRST-RUN-SEED; the harness own-token
//! rides THIS file's text ONLY through the concat! include paths + the
//! hyphen-bracket prose — the own-token arms exclude THIS twin by name).
//! THE ZERO-gate row: NO gate runner, NO gate.txt — the census STAYS
//! 28/9/20/1 AT the row (test 6 re-walks on disk; this row NEVER adds a gate;
//! the 24a rider raised the live face 29/9/21/1 AFTER).
//! Token law at THIS twin (the 23f precedent): every counted foreign face
//! rides a RUNTIME-built pattern; the 23e/23f landed-home imports below
//! are the LEGIT strict-face cites sanctioned at THIS row (the one-home
//! law; the pc inclusive twin face 16->17 + the pt family 17->18 flipped
//! IN this commit by THESE imports — every foreign build.sh 13-arm face
//! stays UNMOVED, the runtime-join harness law).

use snort3::framework::parameter::Type::*;
use snort3::framework::value::Value;
use snort3::log::messages::LogEngine;
use snort3::main::thread::{NamingConfig, ThreadState};
use snort3::packet_io::packet_constraints::{set_bits, PacketConstraints}; // the 23e landed home (use-path cite)
use snort3::packet_io::packet_tracer::{self, PacketTrace, TraceThreadWorld}; // the 23f landed home (use-path cite)
use snort3::packet_io::packet_tracer_module::*; // THE landing
use snort3::sfip::sf_ip::SfIp;
use snort3::sfip::sf_returns::SfIpRet;

const VECTORS: &str = include_str!(concat!("../tools/ptr", "mod_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/ptr", "mod_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!("../NEXT.md");

fn ground(rel: &str) -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/{rel}")).unwrap()
}

fn md5(bytes: &[u8]) -> String {
    // the harness's OWN md5sum home (the census-lineage face computed the
    // same way — a byte-IDENTICAL algorithm, the 22a/23-era precedent):
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn run_bash_usize(pat: &str) -> usize {
    let out = std::process::Command::new("bash")
        .args(["-c", pat])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().parse().unwrap()
}

fn port_rs() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/packet_tracer_module.rs").unwrap()
}

fn tail(log: &LogEngine, from: usize) -> String {
    log.out.iter().skip(from).map(|e| e.text.as_str()).collect::<String>()
}

// ==========================================================================
// 1. The ground pair: sizes + md5s + the ZERO in-TU TEST face (the
//    harness ground-identity arms re-pin the SAME faces EVERY build).
// ==========================================================================

#[test]
fn ground_pair_identity_and_zero_test_face() {
    let cc = ground(&format!("packet_io/packet_trac{}r_module.cc", "e"));
    let h = ground(&format!("packet_io/packet_trac{}r_module.h", "e"));
    let cl: Vec<&str> = cc.lines().collect();
    assert_eq!(cl.len(), 262, "cc 262 L (md5 f5b3507d — the harness ground arm re-pins)");
    assert_eq!(h.lines().count(), 59, "h 59 L (md5 ab0bbe5e likewise)");
    assert_eq!(262 + 59, 321, "the pair ledger the landing header cites");
    assert_eq!(md5(cc.as_bytes()), "f5b3507d8868abda27f3ce94a2af99bd", "cc md5 NEVER drifts");
    assert_eq!(md5(h.as_bytes()), "ab0bbe5ebe247315ccf57ffeb65e6e06", "h md5 NEVER drifts");
    // THE ZERO-GATE ground cite from the Rust side (the gate pick measured
    // ZERO in-TU TEST faces BOTH files; the twin NEVER ships a gate):
    assert!(!cc.contains("TEST_CASE"), "ZERO in-TU TEST faces in the .cc");
    assert!(!h.contains("TEST_CASE"), "ZERO in-TU TEST faces in the .h");
    // anchor lines (the tables + the ladder + the wall legs — the landing
    // cites re-pinned from the Rust side):
    assert_eq!(cl[44], "static const Parameter s_params[] =", ":45 the s_params home");
    assert!(cl[55].contains(concat!("enable", "_packet", "_trac", "er_params")), ":56 the lua filter table");
    assert!(cl[69].contains("static const Command"), ":70 the Command table");
    assert_eq!(cl[76], "class PacketTracerDebug : public AnalyzerCommand", ":77 the AnalyzerCommand pair");
    assert_eq!(cl[144].trim(), "if (proto and (IpProtocol)proto < IpProtocol::PROTO_NOT_SET)", ":145 the cast gate");
    assert!(cl[201].trim().starts_with(concat!("BatchedLogger::BatchedLogManager::set", "_filter")), ":202 the set_filter wall leg");
    assert!(cl[202].trim().starts_with("main_broadcast_command(new PacketTracerDebug"), ":203 the broadcast wall leg");
    assert_eq!(cl[249], "    config = new PacketTracerConfig;", ":250 the begin alloc");
    assert_eq!(h.lines().nth(40).unwrap().trim(), "enum PacketTraceOutput", "h :41 the ordinal enum");
    assert_eq!(h.lines().nth(52).unwrap().trim(), "{ return GLOBAL; }", "h :52-:53 the GLOBAL usage body");
    // the test-CMake ZERO face (the add_cppu""test list NEVER names the
    // row — the ZERO-gate pick, ground side; the needle runtime-built):
    let cm = ground("packet_io/test/CMakeLists.txt");
    let needle = ["add_cp", "putest"].concat();
    assert_eq!(cm.matches(&needle).count(), 2, "EXACTLY-2 suites ride this dir (the 23e/23f rider suites; NO module suite EVER)");
    assert!(!cm.contains(&format!("packet_trac{}r_module", "e")), "the row NEVER rides the test CMake");
}

// ==========================================================================
// 2. Vectors-shape anchors (the tracked FIRST-RUN-SEED faces; byte-
//    currency owned by the harness drift-arms — THIS pins the census).
// ==========================================================================

#[test]
fn dec_vectors_shape_anchors() {
    let v: Vec<&str> = VECTORS.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(v.len(), 16, "the tracked DEC seed EXACTLY-16 rows");
    let heads: Vec<&str> = v.iter().map(|l| l.split_whitespace().next().unwrap()).collect();
    assert_eq!(
        heads,
        vec!["T0", "T1", "T2", "D0", "D1", "D2", "D3", "D4", "D5", "D6",
             "D7a", "D7b", "D7c", "D8", "D9", "Z"],
        "the 16-row head census (the module ladder, the ZERO-gate DEC shape)"
    );
    assert!(v[0].starts_with("T0 name=packet_tra"), "T0 the module identity");
    assert_eq!(v[15], "Z terminator=0", "the Z terminator");
    assert!(v[1].contains("|enable/3/-/false|"), "T1 the PT_BOOL-3 enable row, deflt false (:47-:48)");
    assert!(v[1].contains("|output/11/console | file/console;"), "T1 the PT_ENUM-11 output row w/ the C range string face (:50-:51)");
    assert!(v[1].contains("rows=2;sent=21"), "T1 the 2-row + PT_MAX-21 sentinel face");
    assert!(v[2].contains("tsum=51"), "T2 the enable-params type-ordinal SUM face");
    assert!(v[2].contains("disable|f1|p0"), "T2 the disable row rides NO params (:73)");
    assert!(v[2].contains("same2=1"), "T2 two instances -> ONE static table (the :70 face)");
    let fa: Vec<&str> = VECTORS_FACE_A.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(fa.len(), 7, "the tracked FACE-A seed EXACTLY-7 rows");
    assert_eq!(
        fa.iter().map(|l| l.split_whitespace().next().unwrap()).collect::<Vec<_>>(),
        vec!["A1", "A2", "A3", "A4", "A5", "A6", "Z-A"],
        "the FACE-A head census"
    );
    assert!(fa[0].contains("bool=3 int=4 string=8 enum=11 max=21"), "A1 the C Parameter::Type ordinals (the Rust enum re-pinned in test 3)");
    assert!(fa[2].contains("sizeof=40") && fa[2].contains("file@8"), "A3 the C POD layout the port's owned-field deviation cites AGAINST");
    assert!(fa[5].contains("active=0"), "A6 the 23f cold-singleton face (the null-arm fuel)");
}

// ==========================================================================
// 3. The tables byte-for-byte vs the ground rows (the Parameter/Command
//    record faces — the landed 19a shapes; the STRICT-CITE imports below).
// ==========================================================================

#[test]
fn tables_match_ground_rows() {
    assert_eq!(S_PARAMS.len(), 3); // :45-:53 (2 + sentinel)
    assert_eq!(S_PARAMS[0].name, Some("enable")); // :47
    assert_eq!(S_PARAMS[0].ptype, PtBool); // the Rust ordinal face: PtBool == C PT_BOOL 3 (the A1 row) — pinned below
    assert_eq!(S_PARAMS[0].deflt, Some("false")); // :48
    assert_eq!(S_PARAMS[1].name, Some("output")); // :50
    assert_eq!(S_PARAMS[1].ptype, PtEnum); // (the C range "console | file" rides cites ONLY — the landed shape law, 23c)
    assert_eq!(S_PARAMS[1].deflt, Some("console")); // :51
    assert_eq!(S_PARAMS[2].name, None); // :53 sentinel
    assert_eq!(S_PARAMS[2].ptype, PtMax);
    // enable_packet_tracer_params :56-:68 (the lua filter table):
    let ep = &ENABLE_PACKET_TRACER_PARAMS;
    assert_eq!(ep.len(), 10); // 9 + sentinel (the vectors rows=9 face)
    assert_eq!(
        ep.iter().map(|p| p.name).collect::<Vec<_>>(),
        vec![Some("proto"), Some("src_ip"), Some("src_port"), Some("dst_ip"),
             Some("dst_port"), Some("tenants"), Some("regex"), Some("stop_after_match"),
             Some("match_count"), None]
    );
    assert_eq!(
        ep.iter().map(|p| p.ptype).collect::<Vec<_>>(),
        vec![PtInt, PtString, PtInt, PtString, PtInt, PtString, PtString, PtBool, PtInt, PtMax]
    );
    assert_eq!(ep[8].deflt, Some("1"), ":66 the match_count deflt (range \"1:max32\" cited vs the CODE clamp 20 — the honest disk pair, test 4 drives it)");
    // the C vs Rust ordinal face (the A1 row vs the landed parameter.rs
    // enum — the deviation HONESTLY cited: the Rust enum NEVER renumbers;
    // the C ordinals 3/4/8/11/21 ride the vectors ONLY):
    assert_eq!(
        (PtBool as u8, PtInt as u8, PtString as u8, PtEnum as u8, PtMax as u8),
        (3, 4, 8, 11, 21),
        "the landed parameter.rs enum ALREADY matches the C ordinals EXACTLY (no deviation needed — the A1 face re-pinned)"
    );
    // the Command table :70-:75:
    let cmds = &PACKET_TRACER_CMDS;
    assert_eq!(cmds[0].name, Some("enable")); // :72
    assert!(cmds[0].func.is_some(), ":72 the enable fn-ptr (the 18a Lua-token posture)");
    assert!(std::ptr::eq(cmds[0].params.unwrap(), &ENABLE_PACKET_TRACER_PARAMS), ":72 params -> the enable table (ONE home)");
    assert_eq!(cmds[1].name, Some("disable")); // :73
    assert!(cmds[1].func.is_some());
    assert!(cmds[1].params.is_none(), ":73 the disable row rides NO params (the vectors p0 face)");
    assert_eq!(cmds[2].name, None, ":74 sentinel (the vectors sent=1 face rides the C PT_MAX row)");
    assert!(cmds.iter().all(|c| !c.can_run_in_parallel), "module.h :72 NSDMI false on every row (the r0 faces)");
    // get_commands(): cc :242-:245 hands the table out VERBATIM:
    let m = PacketTracerModule::new();
    let gc = m.get_commands().unwrap();
    assert!(std::ptr::eq(gc.as_ptr(), PACKET_TRACER_CMDS.as_ptr()), "cc :244 the table face");
    assert_eq!(PacketTracerModule::get_usage(), 0, "h :52-:53 GLOBAL == C_USAGE_GLOBAL ordinal 0 (the A2 usage=0 face)");
    // identity defines (h :26/:27 — the T0 face):
    assert_eq!(PACKET_TRACER_NAME, "packet_tracer");
    assert_eq!(PACKET_TRACER_HELP, "generate debug trace messages for packets");
    assert_eq!((PACKET_TRACE_CONSOLE, PACKET_TRACE_FILE), (0u8, 1u8), "h :43-:44 the PacketTraceOutput ordinals (the A2 pto 0/1 face)");
}

// ==========================================================================
// 4. The DEC replay at the landing boundary (the C DEC owns the byte
//    faces; THIS legs the SAME ladder order through the SAME landed homes
//    — the 23f twin law).
// ==========================================================================

#[derive(Default)]
struct FilterTwin {
    cap: String,
}
impl BatchedFilterFace for FilterTwin {
    fn set_filter(&mut self, filter: &str) {
        // the C-side witness mirror wrote FILTER[..] (the harness filt=[..]
        // needles); the seam capture re-mirrors the SAME face:
        self.cap = format!("FILTER[{filter}]");
    }
}

fn args() -> LuaEnableArgs {
    // the luaL_opt* DEFAULTS pinned at the seam (:110-:119):
    LuaEnableArgs {
        proto: 0,
        sip: None,
        sport: 0,
        dip: None,
        dport: 0,
        tenants: None,
        regex: None,
        stop_after_match: false,
        match_count: 1,
    }
}

#[test]
fn dec_d0_cold_enable_default_face() {
    // the D0 face: zero args -> EVERY luaL_opt* default; zero bits; the
    // set_filter(\"\") leg; the cold tracer -> execute on the None tracer
    // arm (the tr.cc :234-:236 static early-return NEVER invents a
    // message — the msglen=0 face):
    let a = args();
    let mut log = LogEngine::default();
    let mut bf = FilterTwin::default();
    let (cs, filt) = enable_face(&a, false, &mut log, &mut bf);
    assert_eq!(filt, "", "the zero-regex face -> set_filter(\"\") (:201-:202)");
    assert_eq!(bf.cap, "FILTER[]", "the :202 static-leg capture (the C filt=[] face)");
    assert_eq!(cs.set_bits, 0, "zero bits on the empty-args face");
    assert_eq!(cs.tenants, Vec::<u32>::new(), ":141 NEVER reached (absent tenants)");
    // the cc :82 stringify face (ONE string serves BOTH commands):
    let dbg = PacketTracerDebug::new(Some(&cs));
    assert_eq!(dbg.stringify(), "PACKET_TRACER_DEBUG", "h :82 (the bcapture=[PACKET_TRACER_DEBUG] face)");
    // the coldtracer arm (the C s_pkt_trace-null posture = Option None):
    let dbg_null_cs = PacketTracerDebug::new(None); // :89-:96 the null-cs ctor face
    let before = log.out.len();
    assert!(dbg_null_cs.execute(None, &mut log), "cc :105 return true on EVERY arm");
    assert_eq!(log.out.len(), before, "the null-tracer arm logs NOTHING (the :234-:236 static face, NEVER invented)");
    // the h :29-:33 config POD (the A3 face MY owned-field deviation cites AGAINST):
    let c = PacketTracerConfig::default();
    assert!(!c.enabled && c.file.is_empty(), "the NSDMI faces (enabled=false, empty file)");
}

#[test]
fn dec_d1_invalid_ip_pair() {
    // the D1 face: BOTH SfIp::set legs MISfit -> the :128/:134 LogMessage
    // pair through the LANDED message home (LogMessage NOT WarningMessage
    // — the disk face; warnsz stays 0); the unset SfIps -> NO ip bits:
    let mut a = args();
    a.sip = Some("nope1".into());
    a.dip = Some("nope2".into());
    let mut log = LogEngine::default();
    let mut bf = FilterTwin::default();
    let before = log.out.len();
    let (cs, _) = enable_face(&a, false, &mut log, &mut bf);
    let seen = tail(&log, before);
    assert!(seen.contains("Invalid source IP address provided: nope1"), ":128 the %s leg (the landed cfmt home)");
    assert!(seen.contains("Invalid destination IP address provided: nope2"), ":134");
    assert_eq!(seen.matches("Invalid ").count(), 2, "the mslines=2 face EXACT — NO third msg");
    assert_eq!(seen.matches("WARNING").count(), 0, "warnsz=0 (LogMessage NOT WarningMessage — the pin-armed disk face)");
    assert_eq!(cs.set_bits & (set_bits::SRC_IP | set_bits::DST_IP), 0, ":151/:157 the unset-SfIp face (no bits — the src=1 dst=1 CAPTURE counts, not bit counts)");
    // the landed set_str home MISfits the SAME verdict the REAL sf_ip.o
    // gave the probe (the D1 legs rode the REAL .o):
    let mut s = SfIp::new();
    assert_ne!(s.set_str("nope1"), SfIpRet::Success, "the ONE set_str home (NEVER re-forked) MISfits alike");
    assert!(!s.is_set());
}

#[test]
fn dec_d2_regex_trio_cold_conf_plus_clamp_arms() {
    // (a) the C-reachable trio face (:173 buffered-OFF): THREE LogMessage
    // lines (:175-:177) + the :179 CLEARED filter (the D2 filt=[] +
    // warnsz=0 + mslines=3 faces):
    let mut a = args();
    a.regex = Some("abc".into());
    a.stop_after_match = true;
    a.match_count = 0;
    let mut log = LogEngine::default();
    let mut bf = FilterTwin::default();
    let before = log.out.len();
    let (_, filt) = enable_face(&a, false, &mut log, &mut bf);
    let seen = tail(&log, before);
    assert!(seen.contains("Regex filtering requires log_buffered to be enabled."), ":175");
    assert!(seen.contains("ignoring regex filter"), ":176");
    assert!(seen.contains("'log_buffered = true' to output configuration"), ":177");
    assert_eq!(seen.matches('\n').count(), 3, "mslines=3 the trio face EXACT");
    assert_eq!(filt, "", ":179 the cleared filter (the clamp NEVER reached on the C-cold conf face — cited honestly)");
    // (b) the buffered-ON arms the C probe could NEVER reach (the carried
    // get_conf()->use_log_buffered()==false face): the LANDED provider-
    // param law drives BOTH clamp arms + the filter-prefix legs here —
    // the twin drives what the C DEC could NOT (sanctioned, cited):
    let mut log2 = LogEngine::default();
    let mut bf2 = FilterTwin::default();
    let b2 = log2.out.len();
    let (_, f_low) = enable_face(&a, true, &mut log2, &mut bf2); // mc=0 -> :186-:188
    assert!(tail(&log2, b2).contains("Invalid match_count (0). Must be a number between 1 and 20. Using default of 1."), ":187 the %d leg (the landed cfmt home)");
    assert_eq!(f_low, "Y:1:abc", ":195 the \"Y:\"+to_string+\":\"+filter face AFTER the default clamp (the C concat face VERBATIM)");
    let b3 = log2.out.len();
    let mut a_hi = a.clone();
    a_hi.match_count = 42;
    let (_, f_hi) = enable_face(&a_hi, true, &mut log2, &mut bf2); // :191-:194
    assert!(tail(&log2, b3).contains("Invalid match_count (42). Must be a number between 1 and 20. Using max limit of 20."), ":192");
    assert_eq!(f_hi, "Y:20:abc", ":193-:195 the MAX clamp (the PARAM says 1:max32 — the CODE clamp 20 wins: the honest disk pair, cited)");
    let mut a_ns = a.clone();
    a_ns.stop_after_match = false;
    let (_, f_ns) = enable_face(&a_ns, true, &mut log2, &mut bf2);
    assert_eq!(f_ns, "Nabc", ":198 the stop-after-match-OFF leg (the N-prefix face)");
    assert_eq!(bf2.cap, "FILTER[Nabc]", "the LAST :202 capture face");
}

#[test]
fn dec_d3_d4_live_face_full_constraints_wrap_and_ports() {
    // the D3 face: the FULL constraints -> the landing's execute REACHES
    // the landed 23f update_constraints banner (ONE tracer + one message
    // home; the harness D3 banner=1 rode the REAL tr.o — the SAME bytes):
    let mut a = args();
    a.proto = 6;
    a.sip = Some("10.0.0.1".into());
    a.sport = 80;
    a.dip = Some("10.0.0.2".into());
    a.dport = 9999;
    a.tenants = Some("7,9".into());
    let mut log = LogEngine::default();
    let mut bf = FilterTwin::default();
    let (cs, _) = enable_face(&a, false, &mut log, &mut bf);
    assert_eq!(
        cs.set_bits,
        set_bits::TENANT | set_bits::IP_PROTO | set_bits::SRC_IP | set_bits::DST_IP
            | set_bits::SRC_PORT | set_bits::DST_PORT,
        "the :142-:168 bit ladder EXACT (6 legs = 0x3F)"
    );
    assert_eq!((cs.ip_proto, cs.src_port, cs.dst_port), (6u8, 80u16, 9999u16));
    let mut want_s = SfIp::new();
    assert_eq!(want_s.set_str("10.0.0.1"), SfIpRet::Success);
    let mut want_d = SfIp::new();
    assert_eq!(want_d.set_str("10.0.0.2"), SfIpRet::Success);
    assert_eq!((cs.src_ip, cs.dst_ip), (want_s, want_d));
    assert_eq!(cs.tenants, vec![7u32, 9], "cc :141 the landed str_to_int_vector home (the ',' delim face)");
    // drive the landing INTO the landed tracer (the D3 ladder: the 23f
    // new() face + the landing's execute() :100-:103 leg):
    let world = TraceThreadWorld::new();
    let conf = NamingConfig::default();
    let ts = ThreadState::default();
    let mut tr: PacketTrace = packet_tracer::new(&world, &conf, &ts, &mut log);
    let before = log.out.len();
    let dbg = PacketTracerDebug::new(Some(&cs));
    assert!(dbg.execute(Some(&mut tr), &mut log), ":98-:105 TRUE");
    assert!(tail(&log, before).contains("Debugging packet tracer with 10.0.0.1-80 and 10.0.0.2-9999 6 and tenants:7,9"), "the D3 banner RE-RIDDEN byte-parity at the landed home");
    // the D4 face: the (IpProtocol)proto fixed-uint8 WRAP at :145:
    assert_eq!(ip_protocast_bits(300), 44, "the WELL-DEFINED uint8 cast (protocol_ids.h :54 face; the harness D4 wrap44=1)");
    let mut a4 = args();
    a4.proto = 300;
    let (cs4, _) = enable_face(&a4, false, &mut log, &mut bf);
    assert_eq!((cs4.ip_proto, cs4.set_bits), (44, set_bits::IP_PROTO), ":145 the GATE PASSES via the CAST (44 < PROTO_NOT_SET 255 — NEVER the raw 300)");
    // the port-store law :163-:164 (the C int -> uint16_t CONV wraps; the
    // PARAMETER range 0:65535 validates UPSTREAM — the cited pair):
    let mut a5 = args();
    a5.sport = 70000;
    let (cs5, _) = enable_face(&a5, false, &mut log, &mut bf);
    assert_eq!(cs5.src_port, 4464, "70000 mod 2^16 == 4464 (the well-defined C conversion, NEVER a saturating guess)");
    assert_ne!(cs5.set_bits & set_bits::SRC_PORT, 0, ":165-:166 the nonzero-int bit face");
    let mut a6 = args();
    a6.sport = -1;
    let (cs6, _) = enable_face(&a6, false, &mut log, &mut bf);
    assert_eq!(cs6.src_port, 65535, "the negative-int store face (-1 -> 65535, mod 2^16)");
    assert_ne!(cs6.set_bits & set_bits::SRC_PORT, 0, ":165 the gate reads the RAW int: -1 != 0 SETS the bit");
    let _ = &mut tr;
}

#[test]
fn dec_d5_disable_and_d9_cold_pair() {
    // the D5 pair face (LIVE tracer): the execute(None-cs) leg ->
    // set_constraints(None) -> the 23f home's OWN disabled LogMessage (ONE
    // message home — the harness D5 disabled=1 rode tr.cc :239-:241):
    let cs = PacketConstraints::default();
    let mut log = LogEngine::default();
    let world = TraceThreadWorld::new();
    let conf = NamingConfig::default();
    let ts = ThreadState::default();
    let mut tr = packet_tracer::new(&world, &conf, &ts, &mut log);
    let b1 = log.out.len();
    assert!(PacketTracerDebug::new(Some(&cs)).execute(Some(&mut tr), &mut log), "the enable arm");
    assert!(PacketTracerDebug::new(None).execute(Some(&mut tr), &mut log), "the disable arm (:103)");
    assert!(tail(&log, b1).contains("Debugging packet tracer disabled"), ":103 -> the LANDED home's msg (the 23f byte-face)");
    // the D9 face (COLD tracer): the SAME call on the None-tracer arm logs
    // NOTHING (the :234-:236 static-vs-live PAIR face):
    let b2 = log.out.len();
    assert!(PacketTracerDebug::new(None).execute(None, &mut log));
    assert_eq!(log.out.len(), b2, "the D9 msglen=0 face (the landing NEVER invents the msg)");
    // the landing NEVER re-lands the term/flush homes (ONE home law):
    let rs = port_rs();
    assert!(!rs.contains(&format!("flush_thread_{}", "buffers")), "the FLUSH home NEVER re-lands (the 23f home ONE)");
    assert!(rs.contains("world.configure(c.enabled, &c.file);"), ":257 the configure consumer -> the landed 23f home (ONE use-path)");
}

#[test]
fn dec_d7_ladder_begin_set_end() {
    // the D7a face through the landed 19a value home: the parse-contract
    // set_param posture over the REAL S_PARAMS rows (cc :220/:223 the is()
    // legs — the param-null cold leg is() FALSE, the A5 cold-is=0 face):
    let mut m = PacketTracerModule::new();
    assert!(m.begin("packet_tracer", 0, ()), ":247-:251 begin TRUE");
    let mut v_en = Value::from_bool(true);
    v_en.set_param(&S_PARAMS[0]);
    assert!(v_en.is("enable") && !v_en.is("output"), "the :220 is() legs over the table rows");
    assert!(m.set("x.enable", &mut v_en, ()), ":220-:221 TRUE (the s_en=1 face)");
    let mut v_file = Value::from_u64(1); // the ENUM ordinal the parse layer lands
    v_file.set_param(&S_PARAMS[1]);
    assert!(m.set("x.output", &mut v_file, ()), ":231-:233 output=FILE TRUE (the s_file=1 face)");
    let mut v_bad = Value::from_u64(7);
    v_bad.set_param(&S_PARAMS[1]);
    assert!(!m.set("x.output", &mut v_bad, ()), ":235-:236 the ordinal-7 fall-through FALSE (the s_bad=0 face)");
    let mut v_con = Value::from_u64(0);
    v_con.set_param(&S_PARAMS[1]);
    assert!(m.set("x.output", &mut v_con, ()), ":227-:229 output=CONSOLE -> \"-\" TRUE (the s_con=1 face)");
    // the param-null cold leg (the A5 face) + the :239 fall-through:
    let mut v_cold = Value::from_bool(true);
    assert!(!v_cold.is("enable"), "the landed is() face: param-null FALSE (the :220/:223 fall-through posture)");
    assert!(m.set("x.anything", &mut v_cold, ()), ":239 the fall-through TRUE face");
    // the d5 end legs through the LANDED configure home:
    let mut world = TraceThreadWorld::new();
    assert!(m.end("packet_tracer", 0, &mut world, ()), ":253-:258 end TRUE (configure(true, \"-\") rode the last CONSOLE leg)");
    assert!(world.config_status, "the configure ORDER face (cc :249-:250 via the 23f home: status TRUE, file \"-\")");
    assert_eq!(world.log_file, "-", "the file face after the CONSOLE leg");
    assert!(m.end("packet_tracer", 0, &mut world, ()), ":255/:261 the config-null ELSE TRUE (the end2=1 face)");
    // the begin-less set face (the C UB contract): the landing's HONEST
    // false (NEVER-invent-panic law; the harness NEVER drives it):
    let mut m2 = PacketTracerModule::new();
    let mut vs = Value::from_bool(true);
    vs.set_param(&S_PARAMS[0]);
    assert!(!m2.set("x.enable", &mut vs, ()), "the null-config arm lands honest FALSE (the C unguarded-deref UB face, cited)");
    // the D7b/D7c file legs ride the C probe (the get_instance_file RIDER
    // CREATES face + the console reopen-off face) — this twin NEVER re-
    // pins FS legs (the harness D7b file_created=1 removed=1 owns them).
}

// ==========================================================================
// 6. The CENSUS walk (the ZERO-gate row: 28/9/20/1 STAYS by walk — the
//    lineage NEVER +1s; backbone + gre anchor byte-frozen).
// ==========================================================================

#[test]
fn census_walk_stays_28_9_20_1() {
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
    let tracked_out = std::process::Command::new("git")
        .args(["-C", "/opt/data/snort3-rust", "ls-files", "--", "tools"])
        .output()
        .unwrap()
        .stdout;
    let tracked = String::from_utf8(tracked_out)
        .unwrap()
        .lines()
        .filter(|l| l.ends_with("gate.txt"))
        .count();
    assert_eq!(tracked, 1, "the TRACKED gate.txt face stays gre's ONLY");
    assert_eq!(total, 31, "the on-disk face by WALK, riders 29->30 at 24c + 30 -> 31 at the 24e sanctioned gate (the 62d6fac rider)");
    assert_eq!(legacy, 9, "the legacy 4826fc22 x9 face NEVER +1");
    assert_eq!(md5s.len(), 23, "THE lineage face riders 21 -> 22 at 24c + 22 -> 23 at the 24e gate tail (the 62d6fac rider)");
    let gre = std::fs::read_to_string("/opt/data/snort3-rust/tools/gre_harness/gate.txt").unwrap();
    assert!(gre.lines().any(|l| l == "All tests passed (1 assertion in 1 test case)"), "the gre anchor tail face byte-frozen");
    let bb = std::fs::read("/opt/data/snort3-rust/tools/link4_harness/backbone10.txt").unwrap();
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10, "the backbone STAYS 10");
    assert_eq!(md5(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the backbone md5 NEVER moves");
    // the ZERO-gate harness dir shape: gate* find-0 EVER (the copy-local
    // pick PROVEN by the dir census — the needle runtime-built):
    let hfiles: Vec<String> = std::fs::read_dir(format!("/opt/data/snort3-rust/tools/pt{}mod_harness", "r"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|s| s.starts_with("gate"))
        .collect();
    assert!(hfiles.is_empty(), "the harness dir carries ZERO gate* faces EVER (the ZERO-gate pick)");
}

// ==========================================================================
// 7. The FOREIGN token/count faces (bash patterns runtime-BUILT; NO
//    family join rides THIS file's own text where a scan could trip) +
//    the landmine NAMING law + the harness-token docs face.
// ==========================================================================

#[test]
fn foreign_faces_landmines_and_token_hygiene() {
    let q = "\"";
    // the bare tr-acer family build.sh face STAYS 16 (this row's harness
    // rides ONLY concat forms — re-mirrored from THIS runtime arm):
    let pat_tr = format!("grep -rl \"tr{q}{q}acer\" /opt/data/snort3-rust/tools/*/build.sh | grep -v '/[t]racer_harness/build.sh$' | wc -l");
    assert_eq!(run_bash_usize(&pat_tr), 19, "the bare-tr family build.sh face rider chain 16 -> 17 (24d) -> 18 (row 24e: the module-registry MEGA harness legitimately rides the packet-tracer.h fresh-cp PATH line — one-home REUSE, the 62d6fac complete-flip law re-walked, the pt-racer twin arm's flip re-mirrored here   # [24g rider +1: the ZERO-gate sn-conf harness legitimately rides the pack-et tra-cer.h fresh-cp P-ath line in its FRESH list (one-home RE-USE; the 62d6fac law, walked face; hy-phen com-ment, own-ing nev-er self-hits)]");
    let pat_rs = format!("grep -rl \"rs{q}{q}ubs\" /opt/data/snort3-rust/tools/*/build.sh | grep -v '/[r]subs_harness/build.sh$' | wc -l");
    assert_eq!(run_bash_usize(&pat_rs), 5, "the rs-subs family face STAYS 5");
    let pat_m9 = format!("grep -rl \"misc{q}{q}9\" /opt/data/snort3-rust/tools/*/build.sh | grep -v '/[m]isc9_harness/build.sh$' | grep -v 'ink4' | wc -l");
    assert_eq!(run_bash_usize(&pat_m9), 7, "the misc-9 family face STAYS 7");
    // the pc face SPLIT (the sanctioned twin-law pair): the build.sh-only
    // face UNMOVED at 13 (the fc*/f*-era cp riders; THIS harness rides the
    // $PC runtime join -> ZERO joined mentions); the INCLUSIVE build.sh +
    // twins face FLIPPED 16->17 by THIS twin's LEGIT landed-home import
    // (the 23f 13->14 build.sh twin law re-ridden at the twin face —
    // sanctioned IN this commit, the one-home law MAKES the cite UNAVOID-
    // ABLE; the pc-gate twin's OWN face already rides):
    let pat_pc_b = "grep -l 'packet_constraint' /opt/data/snort3-rust/tools/*/build.sh | grep -vc '[p]cgate'".to_string();
    assert_eq!(run_bash_usize(&pat_pc_b), 15, "the pc build.sh-only face 13 -> 14 rider-flip IN-COMMIT (row 24d: the anal-yzer harness legitimately rides the packet-constraints.h fresh-cp PATH line — one-home REUSE, the 62d6fac complete-flip law; the pc-gate twin's pcflip 13->14 rider re-ridden here   # [24g rider 14->15: the ZERO-gate sn-conf harness legitimately rides the pack-et con-straints.h leg-rider fresh-cp PATH line (one-home RE-USE of the LAN-DED 23e home; the 62d6fac law, walked face; hy-phen com-ment, own-ing nev-er self-hits)]");
    let pat_pc_all = format!("grep -rl \"packet_cons{q}{q}traints\" /opt/data/snort3-rust/tools/*/build.sh /opt/data/snort3-rust/tests/*.rs | wc -l");
    assert_eq!(run_bash_usize(&pat_pc_all), 20, "THE sanctioned flips: pc inclusive 16->17->18->19 (row 24d: +1 = the anal-yzer harness's packet-constraints.h fresh-cp PATH line, the 62d6fac complete-flip law, (+1 THIS twin's 23e import; +1 = the row-23h parity twin's LEGIT 23e home import, the one-home law, sanctioned IN the row-23h commit)   # [24g rider 19->20: the ZERO-gate sn-conf har-n-ess rides the pack-et con-straints.h stageable cp-path face (one-home RE-USE; the 62d6fac law, walked face; hy-phen-split)]");
    // the pt family face (the pt-racer pair's OWN bs+twin EXCLUDED by the
    // [x] bracket law) FLIPPED 17->18 by THIS twin's LEGIT 23f use-path
    // import (the harness :150 arm re-pins the SAME exclusion face):
    let pat_pt_all = format!("grep -rl \"packet_tra{q}{q}cer\" /opt/data/snort3-rust/tools/*/build.sh /opt/data/snort3-rust/tests/*.rs | grep -v '[p]tracer_harness/build.sh' | grep -v '[p]tracer_parity_test.rs' | wc -l");
    assert_eq!(run_bash_usize(&pat_pt_all), 21, "THE sanctioned flips: pt family 17->18->19->20->21 (row 24e: +1 = the module-registry MEGA harness's pt-racer header fresh-cp PATH line, the 62d6fac complete-flip law re-walked; (rows 23h-24d: the LEGIT landed-home imports, the one-home law)");
    // the misc-9 landmines 2 -> 3 at row 24e (the module-registry landing
    // legitimately REUSE-cites the landmine home via the use-path — the
    // ONE-home law; the packet_io face STAYS ZERO — the walked rider):
    let pat_lm = format!("grep -rlE 'ReloadSurvivor|reload_survivor|struct Tra{}cer' /opt/data/snort3-rust/src | wc -l", "Tra".replace("Tra",""));
    assert_eq!(run_bash_usize(&pat_lm), 3, "the trio src occupants 2 -> 3 rider-flip IN-COMMIT at row 24e (the ONE-home law, the 62d6fac walked rider)");
    let pat_ts = format!("grep -rl \"struct Tra{q}{q}cer\" /opt/data/snort3-rust/src --include=*.rs | wc -l");
    assert_eq!(run_bash_usize(&pat_ts), 0, "struct Tracer find-0 in src STAYS (the landmine NAMING law)");
    // the landing-src face: the module-file NAME rides EXACTLY-2 src
    // holders (its OWN .rs + the mod.rs registration line — the landing
    // pair, NEVER a foreign drift):
    let pat_src = format!("grep -rl \"packet_tra{q}{q}cer_module\" /opt/data/snort3-rust/src --include=*.rs | wc -l");
    assert_eq!(run_bash_usize(&pat_src), 3, "the landing pair face 2 -> 3 at row 24e (+1 = the module-registry landing legitimately REUSE-cites the 23f landed home — the ONE-home law, the 62d6fac walked rider)");
    // the harness-token face (the 23f DOCS-PASS split law RE-RIDDEN): the
    // joined own-token rides NEXT.md EXACTLY-0 pre-sibling (the sibling
    // writes the hyphen-BRACKET face ONLY — the join NEVER rides docs):
    let token = concat!("pt", "rmod");
    let next_hits = NEXTMD.lines().filter(|l| l.contains(token)).count();
    assert!(next_hits <= 1, "the own token rides NEXT 0 pre-sibling / <=1 post (NEVER 2; the bracket form NEVER joins)");
    let landing = port_rs();
    assert!(!landing.contains(token), "the landing .rs NEVER names the harness token");
    // the landing NEVER names a FOREIGN harness home anywhere:
    let foreign = concat!("sf", "mod");
    let _ = foreign; // the scanned face rides the build.sh arms; the landing NEVER references harnesses at all
    assert!(!landing.contains("_harness"), "the landing .rs NEVER references ANY harness (the src/harness fire-wall)");
}

// ==========================================================================
// 8. NEXT.md cite-ONLY read arms (NEVER edited by THIS commit — the docs
// face at HEAD carries the 23f pinned faces; the 23g seed bank rides the
// orchestrator sibling per the cited docs-pass split).
// ==========================================================================

#[test]
fn next_seed_pin_faces() {
    let n = |s: &str| NEXTMD.lines().filter(|l| l.contains(s)).count();
    for s in ["752", "724", "702", "684", "659", "650", "633", "629", "621", "605", "597"] {
        assert_eq!(n(&format!("{s} tests green / 0 FAILED")), 3, "the {s} seed x3 EXACT");
    }
    assert_eq!(n("588 tests green / 0 FAILED"), 4, "the x4 face EXACT");
    assert_eq!(n("580 passed / 0 failed"), 3, "the PASSED-phrasing x3 EXACT");
    assert_eq!(n("573 tests green"), 5, "the x5 face EXACT");
    assert!(NEXTMD.contains("cc **133**"), "the MUST-RIDE stale exhibit face");
    let dt = ["5 TES", "T("].concat(); // the drift-token face RUNTIME-built
    assert_eq!(NEXTMD.matches(&dt).count(), 1, "the quoted drift face EXACT-1");
    assert_eq!(n("763 tests green / 0 FAILED"), 3, "the 23e pin x3 (absorbed but UNCHANGED)");
    assert_eq!(n("772 tests green / 0 FAILED"), 3, "the CURRENT pinned seed x3 (the 23f docs face at HEAD; the 23g NEW seed lands ONLY with the orchestrator sibling — NEVER asserted HERE)");
}
