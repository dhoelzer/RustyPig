//! Parity test for the row-18j misc icmp _ip PAIR ports — two ground
//! TUs (misc/cd_icmp4_ip.cc 345 L c0744dc1d4d38b3b66c3293acae1c04d /
//! misc/cd_icmp6_ip.cc 162 L 60723a7c04827eb877ae229015b9247c; wc + md5
//!     plus the 345+162=507 SUM re-measured and asserted EVERY build by
//! tools/miscip_harness/build.sh). ZERO-gate row (the daq3/small4
//! clone): combined gate grep 0 x2 + the misc/test/ CppUTest dialect
//! census re-asserted every build -> this suite carries NO up_gate_*
//! set: honest absence, census-cited (and the CppUTest runner stays
//! uninstalled — the E4 face re-armed by every frozen build).
//!
//! Ground truth #1: `tools/miscip_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 23 L md5 43b259ac8b77320ff9ddaa80dde1a36e NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session (per-index assert_eq over want.len()==23). THE R6 EVAL-ORDER
//! RULE REPLAYS: every decode bool is stored BEFORE the summary line
//! and every `EV 116 <sid>` lands BETWEEN the decode call and its
//! printf, NEVER sorted. The order faces: :1/:2 (250 before short19),
//! :9/:10 (254 GT_576 fires THEN DECODE CONTINUES -> `gt576 -> 1` —
//! the pair's non-returning event arm), :18 (the GROUND-DEAD 252 arm
//! carried as the CITE line `IP6 252-unarmed cc:78-fixed-true` — NEVER
//! a fake EV, cite-never-guess).
//!
//! THE ROW'S HEADLINES replayed Rust-side: (a) the is_ip6 RIDER PAIR
//! (vectors:3-5): ver!=4 + ip4-api DIES (251), ver!=4 + ip6-api
//! CONTINUES (pb=16384 lyr=20 — cd_icmp4_ip.cc:69, PLAN R5); (b) the
//! mod_ctor=0/mod_dtor=0 x2 record ASYMMETRY (vectors_faceA:6/:10 —
//! contrast daq3's uniform 1/1 x3 + small4's 1/0/1/1, pin face against
//! ground :325/:326 + :143/:144 nullptr); (c) the pair-same GETIDS face
//! 259/260 decimal; (d) the embed-switch proto_bits ladder 4096/8192/
//! 16384/32768 (decode_data.h :99-:102, ALL-DECIMAL hygiene).
//!
//! Ground truth #2: `tools/miscip_harness/vectors_faceA.txt` — the
//! FACE-A load/walk face (probe.cc, ONE probe x TWO hidden-BUILDING_SO
//! tables through the in-probe PluginManager witness; the STATIC arm is
//! what compiles — cd_icmp4_ip cd_icmp6_ip EXIST nm-EXACTLY-1 each),
//! 11 L md5 e4c47bac93a15af4ecfdc9a0bd1abe62. TRUE NAMES hold x2
//! (file base == table base == NAME walk face): NO drift rider, the
//! tripwire pins the pair NAME side + the ladder contains face
//! (codec_api.rs :113/:115 RESIDENT — the daq3-pass UNLOADED pin at
//! tests/daq3_parity_test.rs:963-:964 NOW TURNS loaded by this row's
//! tables landing; the ladder itself NEVER re-touched).
//!
//! CppUTest dialect face (PLAN §0/§4, 18f discipline): the misc/test/
//! suites carry EXACTLY 10 CppUTest names (TEST_GROUP x3 + TEST( x7:
//! geneve 1+3, gtp 1+2, teredo 1+2; TEST_CASE 0 x3) and NONE includes a
//! pair TU (build.sh pair-include grep 0 x3 every build) — ALL SEVEN
//! TEST bodies were ALREADY Rust-side translated AT 18f
//! (tests/tun_parity_test.rs up_tun_*), NEVER run C-side (CppUTest
//! absent, E4 face). The row's honest posture: the misc PAIR ships ZERO
//! of its own suites; the dialect census rides as a pinned constant
//! face with a cross-file contains proof — translation face, not a
//! re-invention.

use snort3::codecs::cd_icmp4_ip as ip4i;
use snort3::codecs::cd_icmp6_ip as ip6i;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/miscip_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/miscip_harness/vectors_faceA.txt");
/// The 18f translation site (the CppUTest-dialect cross-file proof).
const TUN_TESTS: &str = include_str!("tun_parity_test.rs");

fn buf4096() -> [u8; 4096] {
    [0u8; 4096]
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 23 lines, ordered,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored).
// ==========================================================================
#[test]
fn miscip_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 23, "vectors.txt must hold the full 23-line DEC ladder");

    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };
    // the queue_event witness seam: `EV %u %u` (GID_DECODE 116).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };

    let conf = SnortConfig::default();
    // probe's `extern const snort::BaseApi* cd_*_ip[]` + ctor(nullptr):
    let c4 = ip4i::Icmp4IpCodec::new(); // a4->ctor(nullptr), probe_dec.cc:43
    let c6 = ip6i::Icmp6IpCodec::new(); // a6->ctor(nullptr), probe_dec.cc:78

    // ---- cd_icmp4_ip: the six-event decode ladder ----
    // vectors:1/:2 — RawData(nullptr,z,19): z[4096] face (:56 TRUNCATED 250).
    {
        let z = buf4096();
        let raw = fw::RawData { data: &z, len: 19 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 short19 -> {}", b as u8));
    }
    // vectors:3/:4 — p[40] p[0]=0x65 ver nibble 6, ip4-api (is_ip6 false)
    // -> the :69 COMPOUND gate DIES (VER_MISMATCH 251).
    {
        let mut pp = [0u8; 40];
        pp[0] = 0x65;
        let raw = fw::RawData { data: &pp, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 ver6-ip4api -> {}", b as u8));
    }
    // vectors:5 — THE R5 is_ip6 RIDER: p[48] p[0]=0x65 p[9]=1 (ICMPV4),
    // ip_api = ip6 face (b6 zeroed b6[0]=0x60 -> dgram_len 0+40, ip.cc
    // :247-:251 IAT_6, NEVER the embedded window) -> SURVIVES, proto
    // ICMPV4 arm, lyr = hlen 20.
    {
        let mut pp = [0u8; 48];
        pp[0] = 0x65;
        pp[9] = 1;
        let raw = fw::RawData { data: &pp, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData { is_ip6: true, dgram_len: 40 };
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!(
            "IP4 ver6-ip6rider -> {} pb={} lyr={}",
            b as u8, cd.proto_bits, cd.lyr_len
        ));
    }
    // vectors:6/:7 — p[22] p[0]=0x46: IHL 6 -> hlen 24 > raw.len 22
    // (:77/:79 DGRAM_LT 252).
    {
        let mut pp = [0u8; 22];
        pp[0] = 0x46;
        let raw = fw::RawData { data: &pp, len: 22 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 hlen24-22 -> {}", b as u8));
    }
    // vectors:8/:9 — p[27] p[0]=0x45: ip_len 27-20=7 < 8 (:89/:91
    // PAYLOAD_LT_64 253).
    {
        let mut pp = [0u8; 27];
        pp[0] = 0x45;
        let raw = fw::RawData { data: &pp, len: 27 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 pay7 -> {}", b as u8));
    }
    // vectors:10/:11 — p[40] p[0]=0x45 p[9]=17, b4[2..3]=0xEA60 == 60000
    // > 576 (ip.cc:247 IAT_4 = the SET header, probe set_ip4 THEN the
    // b4 mutate) -> GT_576 254 EVENT-THEN-CONTINUE, UDP arm pb=8192,
    // lyr = hlen 20. THE row's non-returning-arm order face.
    {
        let mut pp = [0u8; 40];
        pp[0] = 0x45;
        pp[9] = 17;
        let raw = fw::RawData { data: &pp, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData { dgram_len: 60000, ..Default::default() };
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!(
            "IP4 gt576 -> {} pb={} lyr={}",
            b as u8, cd.proto_bits, cd.lyr_len
        ));
    }
    // vectors:12/:13 — p[40] p[0]=0x45 p[6]=0x01: frag off 256 != 0
    // (:102/:105 FRAGOFFSET 255 + false).
    {
        let mut pp = [0u8; 40];
        pp[0] = 0x45;
        pp[6] = 0x01;
        let raw = fw::RawData { data: &pp, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 fragoff -> {}", b as u8));
    }
    // embed-switch faces (the gt576 arm above already rode the UDP arm):
    // vectors:14 p[48] p[9]=6 TCP (:109/:112 -> 4096). set_ip4 re-zeroes
    // b4 every call -> dgram_len 0 on every embed arm (probe face).
    {
        let mut pp = [0u8; 48];
        pp[0] = 0x45;
        pp[9] = 6;
        let raw = fw::RawData { data: &pp, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 embed-tcp -> {} pb={}", b as u8, cd.proto_bits));
    }
    // vectors:15 p[48] p[9]=1 ICMPV4 (:119 -> 16384).
    {
        let mut pp = [0u8; 48];
        pp[0] = 0x45;
        pp[9] = 1;
        let raw = fw::RawData { data: &pp, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 embed-icmp -> {} pb={}", b as u8, cd.proto_bits));
    }
    // vectors:16 p[48] p[9]=47 default (:122-:123 -> 32768).
    {
        let mut pp = [0u8; 48];
        pp[0] = 0x45;
        pp[9] = 47;
        let raw = fw::RawData { data: &pp, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = c4.decode(&raw, &mut cd, &d, &mut sink);
        push(format!("IP4 embed-other -> {} pb={}", b as u8, cd.proto_bits));
    }

    // ---- cd_icmp6_ip: three-name census (252 GROUND-DEAD, cite line) ----
    // vectors:17/:18 — 39-byte window (:61/:63 TRUNCATED 250).
    {
        let z = buf4096();
        let raw = fw::RawData { data: &z, len: 39 };
        let mut cd = fw::CodecData::new(Some(&conf), ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6);
        let b = c6.decode(&raw, &mut cd, &mut sink);
        push(format!("IP6 short39 -> {}", b as u8));
    }
    // vectors:19/:20 — q[40] q[0]=0x45 ver nibble 4 (:71/:73 VER 251).
    {
        let mut q = [0u8; 40];
        q[0] = 0x45;
        let raw = fw::RawData { data: &q, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6);
        let b = c6.decode(&raw, &mut cd, &mut sink);
        push(format!("IP6 ver4 -> {}", b as u8));
    }
    // vectors:21 — THE GROUND-DEAD second gate (:77 cppcheck face): the
    // 252 arm can NEVER fire (first gate pins raw.len>=40); the honest
    // CITE line, NEVER a fake EV — the decode NEVER runs for this line.
    push("IP6 252-unarmed cc:78-fixed-true".to_string());
    // vectors:22 — q[40] q[0]=0x60 q[6]=6 next=TCP (:97/:100 + :118 lyr
    // FIXED 40, NOT hlen-driven — the mate contrast).
    {
        let mut q = [0u8; 40];
        q[0] = 0x60;
        q[6] = 6;
        let raw = fw::RawData { data: &q, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6);
        let b = c6.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "IP6 next-tcp -> {} pb={} lyr={}",
            b as u8, cd.proto_bits, cd.lyr_len
        ));
    }
    // vectors:23 — q[40] q[0]=0x60 q[6]=47 default (:111-:112).
    {
        let mut q = [0u8; 40];
        q[0] = 0x60;
        q[6] = 47;
        let raw = fw::RawData { data: &q, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6);
        let b = c6.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "IP6 next-default -> {} pb={} lyr={}",
            b as u8, cd.proto_bits, cd.lyr_len
        ));
    }

    assert_eq!(got_len(&out), 23);
    let got = out.borrow();
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

fn got_len(out: &std::rc::Rc<std::cell::RefCell<Vec<String>>>) -> usize {
    out.borrow().len()
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 11 lines (probe.cc in-probe
//    load_plugins witness walking the TWO hidden-BUILDING_SO tables
//    through the STATIC arm — the tables ARE cd_icmp4_ip/cd_icmp6_ip,
//    nm EXACTLY-1 each, PLAN §4).
// ==========================================================================
#[test]
fn miscip_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 11, "vectors_faceA.txt must hold the full 11-line walk");

    let mut got: Vec<String> = Vec::new();

    // the witness load face: for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name)
    for tab in [ip4i::CD_ICMP4_IP, ip6i::CD_ICMP6_IP] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
    }
    got.push("LOADS 2".to_string());

    // probe.cc tabs[] = { cd_icmp4_ip[0], cd_icmp6_ip[0] } — TRUE NAMES:
    // every name prints its file base (the pair carries NO drift rider;
    // NAME == table base == file base, the cd_auth drift family ABSENT,
    // build.sh NAME/HELP macro pins :37-:38 / :34+:37).
    let tabs = [ip4i::CD_ICMP4_IP, ip6i::CD_ICMP6_IP];
    let nm = ["icmp4_ip", "icmp6_ip"];
    for (tag, tab) in nm.iter().zip(tabs.iter()) {
        let a = tab[0];
        got.push(format!(
            "API {} type={} size={} ver={} name={}",
            tag, a.ptype, a.size, a.api_version, a.name
        ));
        got.push(format!("HELP {} {}", tag, a.help));
        // THE asymmetry PIN: mod_ctor=0 mod_dtor=0 x2 (ground cc:325/:326
        // + cc:143/:144 nullptr — the pair face vs daq3 1/1 x3 / small4
        // 1/0/1/1).
        got.push(format!(
            "{} mod_ctor={} mod_dtor={}",
            tag, a.mod_ctor as u8, a.mod_dtor as u8
        ));
        // ca->ctor(nullptr); c->get_protocol_ids(ids); dtor(c):
        if *tag == "icmp4_ip" {
            let mut ids = Vec::new();
            ip4i::Icmp4IpCodec::new().get_protocol_ids(&mut ids);
            for id in ids {
                got.push(format!("GETIDS {} {}", tag, id)); // DECIMAL (0x0103 = 259)
            }
        } else {
            let mut ids = Vec::new();
            ip6i::Icmp6IpCodec::new().get_protocol_ids(&mut ids);
            for id in ids {
                got.push(format!("GETIDS {} {}", tag, id)); // 0x0104 = 260
            }
        }
    }

    assert_eq!(got.len(), 11);
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "faceA line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 3. HIDDEN-TABLE tripwire — the pair table-face pins. The C tables
//    live ONLY under `#ifdef BUILDING_SO` (NO): cd_icmp4_ip.cc :336-
//    :343 (table :339, record slot :342) / cd_icmp6_ip.cc :154-:161
//    (table :157, record slot :160) — sed-verbatim in build.sh EVERY
//    build. Rust face = the landed-row pattern: table const identity
//    pins the C table name, feed identity pins the record.
// ==========================================================================
#[test]
fn miscip_hidden_table_tripwire() {
    // THE hidden-table NAME pins (cites cd_icmp4_ip.cc:339 table stmt /
    // cd_icmp6_ip.cc:157, sed-verbatim in build.sh EVERY build): the
    // Rust table consts carry the C symbol words EXACTLY — read the
    // committed source faces and pin the table-name lines (renaming a
    // const trips THIS assert; the daq3/small4 drift-tripwire posture,
    // grep face Rust-side).
    const IP4_RS: &str = include_str!("../src/codecs/cd_icmp4_ip.rs");
    const IP6_RS: &str = include_str!("../src/codecs/cd_icmp6_ip.rs");
    assert!(IP4_RS.contains("pub const CD_ICMP4_IP: CodecTable = &[&ICMP4_IP_API];"),
        "the cd_icmp4_ip hidden-table const face drifted");
    assert!(IP6_RS.contains("pub const CD_ICMP6_IP: CodecTable = &[&ICMP6_IP_API];"),
        "the cd_icmp6_ip hidden-table const face drifted");
    // the hidden-BUILDING_SO cite lines ride BOTH source faces:
    assert!(IP4_RS.contains("cd_icmp4_ip[]")); // the cc:339 static-arm cite
    assert!(IP6_RS.contains("cd_icmp6_ip[]")); // the cc:157 static-arm cite

    // EXACTLY-1 entry per table == the `{ &*_ip_api.base, nullptr }` C
    // face (the harness walk loaded EXACTLY 2 across the pair, vectors
    // _faceA:3 `LOADS 2`):
    assert_eq!(ip4i::CD_ICMP4_IP.len(), 1);
    assert_eq!(ip6i::CD_ICMP6_IP.len(), 1);

    // feed identity: CD_ICMP4_IP[0] == &ICMP4_IP_API (cc:342 feeds
    // &icmp4_ip_api.base) / CD_ICMP6_IP[0] == &ICMP6_IP_API (cc:160):
    assert!(std::ptr::eq(ip4i::CD_ICMP4_IP[0], &ip4i::ICMP4_IP_API));
    assert!(std::ptr::eq(ip6i::CD_ICMP6_IP[0], &ip6i::ICMP6_IP_API));

    // TRUE-NAME pair (file base == table base == NAME): the ladder
    // entries "cd_icmp4_ip"/"cd_icmp6_ip" ride STATIC_CODEC_EXTERN_NAMES
    // (RESIDENT codec_api.rs :113/:115 — NEVER re-touched; the daq3
    // test's EXISTENCE-but-UNLOADED pin at daq3_parity_test.rs :958-
    // :964 TURNS loaded HERE: the pair tables now land). NO file-vs-
    // table drift face for the pair (contrast cd_auth: the 18h row pins
    // its OWN pair there, this pins the pair's absence):
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp4_ip"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp6_ip"));
    assert!(!capi::STATIC_CODEC_EXTERN_NAMES.contains(&"icmp4_ip"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18j adds NO new externs"
    );

    // NAME side (the walk prints these words, faceA:4-:5/:8-:9):
    assert_eq!(ip4i::CD_ICMP4_IP_NAME, "icmp4_ip"); // cc:37
    assert_eq!(ip4i::ICMP4_IP_API.name, "icmp4_ip"); // cc:314 struct, cc:323 slot
    assert_eq!(ip6i::CD_ICMP6_IP_NAME, "icmp6_ip"); // cc:34 (the #ifndef-wrapped macro)
    assert_eq!(ip6i::ICMP6_IP_API.name, "icmp6_ip"); // cc:132 struct, cc:141 slot
}

// ==========================================================================
// 4. THE record census — the pair is mod-pair ZERO x2 (THE asymmetry
//    pin vs daq3's uniform 1/1 x3 and small4's 1/0/1/1): 112/1900547/
//    PT_CODEC x2 + ctor/dtor set + the four g/t nullptr arms false x4.
// ==========================================================================
#[test]
fn miscip_record_census() {
    for a in [ip4i::CD_ICMP4_IP[0], ip6i::CD_ICMP6_IP[0]] {
        assert_eq!(a.ptype, fw::PT_CODEC);
        assert_eq!(a.size, 112); // sizeof(CodecApi), the probe pin (faceA:4/:8)
        assert_eq!(a.api_version, 1900547);
        assert_eq!(a.version, 0);
        assert_eq!(a.features, fw::PLUGIN_SO_RELOAD);
        assert_eq!(a.options, fw::API_OPTIONS);
        // THE pair-uniform mod PAIR ZERO (faceA:6/:10 all mod_ctor=0 —
        // ground nullptr cc:325/:326 + cc:143/:144):
        assert!(!a.mod_ctor, "{} mod_ctor MUST be the nullptr arm", a.name);
        assert!(!a.mod_dtor, "{} mod_dtor MUST be the nullptr arm", a.name);
        assert!(!a.pinit);
        assert!(!a.pterm);
        assert!(!a.tinit);
        assert!(!a.tterm);
        assert!(a.ctor);
        assert!(a.dtor);
    }
    // HELP faces (faceA:5/:9, sed pins at cc:38 / cc:37):
    assert_eq!(ip4i::ICMP4_IP_API.help, "support for IP in ICMPv4");
    assert_eq!(ip6i::ICMP6_IP_API.help, "support for IP in ICMPv6");
}

// ==========================================================================
// 5. The misc/test/ CppUTest dialect census (PLAN §0/§4, STOP-flag
//    probe NEGATIVE): EXACTLY 10 names land on disk — TEST_GROUP x3 +
//    TEST( x7 = geneve 4 (1+3) / gtp 3 (1+2) / teredo 3 (1+2),
//    TEST_CASE 0 x3, pair-TU includes 0 x3 (build.sh re-runs every
//    build). ALL SEVEN TEST bodies were translated Rust-side AT 18f
//    (18f discipline: translated NEVER run C-side, the uninstalled-
//    CppUTest E4 face) — the cross-file contains proof below reads the
//    ACTUAL 18f file, air never.
// ==========================================================================
#[test]
fn miscip_cpputest_dialect_census() {
    // The 10 measured names (ground cites: geneve_codec_test.cc:103/
    // :107/:121/:150, gtp_codec_test.cc:87/:93/:116, teredo_codec_test
    // .cc:86/:90/:103):
    const NAMES: [&str; 10] = [
        "TEST_GROUP(geneve_codec_tests)",
        "TEST(geneve_codec_tests, decode)",
        "TEST(geneve_codec_tests, geneve_lyr)",
        "TEST(geneve_codec_tests, geneve_lyr_no_options)",
        "TEST_GROUP(gtp_codec_tests)",
        "TEST(gtp_codec_tests, gtpv1_header_fills_packet_no_inner_read)",
        "TEST(gtp_codec_tests, gtpv0_header_fills_packet_no_inner_read)",
        "TEST_GROUP(teredo_codec_tests)",
        "TEST(teredo_codec_tests, rejects_payload_ending_after_auth_indicator)",
        "TEST(teredo_codec_tests, rejects_payload_ending_after_origin_indicator)",
    ];
    let per_suite = |needle: &str| NAMES.iter().filter(|n| n.contains(needle)).count();
    assert_eq!(per_suite("geneve_codec_tests"), 4, "geneve 1 GROUP + 3 TEST");
    assert_eq!(per_suite("gtp_codec_tests"), 3, "gtp 1 GROUP + 2 TEST");
    assert_eq!(per_suite("teredo_codec_tests"), 3, "teredo 1 GROUP + 2 TEST");

    // ZERO names reference the pair (the build.sh pair-include grep
    // 0 x3 face — the misc PAIR ships NO suite of its own):
    for n in NAMES.iter() {
        assert!(!n.contains("icmp4_ip") && !n.contains("icmp6_ip"), "census lie: {n}");
    }

    // The 18f translations EXIST (all 7 TEST names mirrored up_tun_*):
    assert!(TUN_TESTS.contains("fn up_tun_geneve_decode"));
    assert!(TUN_TESTS.contains("fn up_tun_geneve_geneve_lyr("));
    assert!(TUN_TESTS.contains("fn up_tun_geneve_geneve_lyr_no_options"));
    assert!(TUN_TESTS.contains("fn up_tun_gtp_gtpv1_header_fills_packet_no_inner_read"));
    assert!(TUN_TESTS.contains("fn up_tun_gtp_gtpv0_header_fills_packet_no_inner_read"));
    assert!(TUN_TESTS.contains("fn up_tun_teredo_rejects_payload_ending_after_auth_indicator"));
    assert!(TUN_TESTS.contains("fn up_tun_teredo_rejects_payload_ending_after_origin_indicator"));
}

// ==========================================================================
// 6. UNIT: the embed-switch census x2 TUs (4 arms each; the same four
//    decode_data.h :99-:102 bits, DECIMAL 4096/8192/16384/32768 —
//    icmp6_ip's GROUND ICMPV4 arm (cc:108, NOT ICMPV6) transcribed).
// ==========================================================================
#[test]
fn up_miscip_embed_switch_pair() {
    let conf = SnortConfig::default();
    let unit4 = |proto: u8| -> (u32, u16) {
        let mut pp = [0u8; 48];
        pp[0] = 0x45;
        pp[9] = proto;
        let raw = fw::RawData { data: &pp, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        let b = ip4i::Icmp4IpCodec::new().decode(&raw, &mut cd, &d, &mut |_g, _s| {});
        assert!(b);
        (cd.proto_bits, cd.lyr_len)
    };
    assert_eq!(unit4(6), (4096, 20));  // TCP    cc:111-:112
    assert_eq!(unit4(17), (8192, 20)); // UDP    cc:115-:116
    assert_eq!(unit4(1), (16384, 20)); // ICMPV4 cc:119-:120
    assert_eq!(unit4(47), (32768, 20)); // default cc:122-:123

    let unit6 = |next: u8| -> (bool, u32, u16) {
        let mut q = [0u8; 40];
        q[0] = 0x60;
        q[6] = next;
        let raw = fw::RawData { data: &q, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6);
        let b = ip6i::Icmp6IpCodec::new().decode(&raw, &mut cd, &mut |_g, _s| {});
        (b, cd.proto_bits, cd.lyr_len)
    };
    assert_eq!(unit6(6), (true, 4096, 40));  // TCP cc:99-:100
    assert_eq!(unit6(17), (true, 8192, 40)); // UDP cc:103-:104
    assert_eq!(unit6(1), (true, 16384, 40)); // THE GROUND ICMPV4 arm cc:108 (+FIXIT-M comment)
    assert_eq!(unit6(47), (true, 32768, 40)); // default cc:111-:112
    // lyr_len FIXED 40 (cc:118) — the mate's hlen-driven contrast: both
    // faceA DEC arms lyr=40, the icmp4 arms lyr=20 (hlen of 0x45/0x65).
}

// ==========================================================================
// 7. UNIT: the gt576 EVENT-THEN-CONTINUE headline + the fragoffset
//    else-arm + the is_ip6 rider pair (the R5 faces, unit-decomposed
//    beyond the ordered replay).
// ==========================================================================
#[test]
fn up_miscip_gt576_continue_and_rider() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = ip4i::Icmp4IpCodec::new();

    // GT_576: ONE event, decode TRUE, UDP arm proceeds (cc:97-:99 no
    // return): 254 + true + pb 8192.
    {
        let mut pp = [0u8; 40];
        pp[0] = 0x45;
        pp[9] = 17;
        let raw = fw::RawData { data: &pp, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData { dgram_len: 577, ..Default::default() }; // boundary >576 only
        let b = c.decode(&raw, &mut cd, &d, &mut sink);
        assert!(b, "254 must NOT return");
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 254)]);
        assert_eq!(cd.proto_bits, 8192);
        // the 576 boundary itself: dgram_len == 576 -> NO event:
        let d0 = ip4i::Icmp4IpDecodeData { dgram_len: 576, ..Default::default() };
        let mut cd0 = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        assert!(c.decode(&raw, &mut cd0, &d0, &mut sink));
        assert_eq!(std::mem::take(&mut *evs.borrow_mut()).len(), 0);
    }
    // FRAGOFFSET: off()!=0 (bytes 6-7 BE, (off & 0x1FFF) << 3) -> 255 +
    // false, NO embed switch (cc:102-:106).
    {
        let mut pp = [0u8; 40];
        pp[0] = 0x45;
        pp[7] = 0x01; // off_w_flags 0x0001 -> (1<<3)=8 != 0
        let raw = fw::RawData { data: &pp, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData::default();
        assert!(!c.decode(&raw, &mut cd, &d, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 255)]);
        assert_eq!(cd.proto_bits, 0, "no switch arm after the else-return");
    }
    // THE R5 rider pair (cc:69 compound, BOTH arms):
    {
        let mut pp = [0u8; 48];
        pp[0] = 0x65; // ver 6
        pp[9] = 1;
        let raw = fw::RawData { data: &pp, len: 48 };
        // arm 1: ip4 api -> DIES 251
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData { is_ip6: false, dgram_len: 40 };
        assert!(!c.decode(&raw, &mut cd, &d, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 251)]);
        // arm 2: ip6 api -> CONTINUES (the probe-face pb=16384 lyr=20)
        let mut cd = fw::CodecData::new(Some(&conf), ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4);
        let d = ip4i::Icmp4IpDecodeData { is_ip6: true, dgram_len: 40 };
        assert!(c.decode(&raw, &mut cd, &d, &mut sink));
        assert_eq!(std::mem::take(&mut *evs.borrow_mut()).len(), 0);
        assert_eq!(cd.proto_bits, 16384);
        assert_eq!(cd.lyr_len, 20); // hlen of 0x65 = (5<<2), NOT 48
    }
    // cd_icmp6_ip GROUND-DEAD gate honesty: 40+ windows NEVER fire the
    // DEAD arm's event (the cc:77 cppcheck face; the unit's ZERO-event
    // pins vectors:21's cite line the other way).
    {
        let mut q = [0u8; 40];
        q[0] = 0x60;
        q[6] = 1; // ICMPV4 ground arm (NOT ICMPV6 — transcribed bug-face)
        let raw = fw::RawData { data: &q, len: 40 };
        let mut cd = fw::CodecData::new(Some(&conf), ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6);
        assert!(ip6i::Icmp6IpCodec::new().decode(&raw, &mut cd, &mut sink));
        assert_eq!(std::mem::take(&mut *evs.borrow_mut()).len(), 0, "zero events: the DEAD 252 NEVER fires");
    }
}

// ==========================================================================
// 8. UNIT: the row-scoped vocab census (decode_data.h :99-:102 bits,
//    protocol_ids.h :130-:131 ids — the PYPIN-decimal identity the
//    harness build.sh pins ground-vs-RUST both ways; the pair's
//    row-scoped duplicate ruling per the cd_icmp6.rs :183 cite).
// ==========================================================================
#[test]
fn up_miscip_row_scoped_vocab() {
    assert_eq!(ip4i::PROTO_BIT__TCP_EMBED_ICMP, 0x001000); // h:99
    assert_eq!(ip4i::PROTO_BIT__UDP_EMBED_ICMP, 0x002000); // h:100
    assert_eq!(ip4i::PROTO_BIT__ICMP_EMBED_ICMP, 0x004000); // h:101
    assert_eq!(ip4i::PROTO_BIT__ICMP_EMBED_OTHER, 0x008000); // h:102
    assert_eq!(ip6i::PROTO_BIT__TCP_EMBED_ICMP, ip4i::PROTO_BIT__TCP_EMBED_ICMP);
    assert_eq!(ip6i::PROTO_BIT__ICMP_EMBED_OTHER, ip4i::PROTO_BIT__ICMP_EMBED_OTHER);
    assert_eq!(ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4, 0x0103); // h:130 == 259
    assert_eq!(ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6, 0x0104); // h:131 == 260
    assert_eq!(ip4i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4, 259); // faceA:7 DECIMAL pin
    assert_eq!(ip6i::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6, 260); // faceA:11
    assert_eq!(ip4i::IP4_HEADER_LEN, 20);  // ipv4.h:38
    assert_eq!(ip6i::IP6_HEADER_LEN, 40);  // ipv6.h:31 (sed cite face)
    // the resident six-family sids (codec_module.rs :125-:130, ZERO new
    // constants — the 6/3-unique event-name census, PYPIN both ways):
    use snort3::codecs::codec_module as cm;
    assert_eq!(cm::CodecSid::DECODE_ICMP_ORIG_IP_TRUNCATED as u32, 250);
    assert_eq!(cm::CodecSid::DECODE_ICMP_ORIG_IP_VER_MISMATCH as u32, 251);
    assert_eq!(cm::CodecSid::DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP as u32, 252);
    assert_eq!(cm::CodecSid::DECODE_ICMP_ORIG_PAYLOAD_LT_64 as u32, 253);
    assert_eq!(cm::CodecSid::DECODE_ICMP_ORIG_PAYLOAD_GT_576 as u32, 254);
    assert_eq!(cm::CodecSid::DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET as u32, 255);

    // The get_proto_name seam face (the EXACTLY-+1 witness mirror): the
    // Rust port NEVER invents the C++ PacketManager — the observable
    // harness-witness string is the modeled face (witness_miscip.cc:25-
    // :26), log OUTPUT cite-never-vectorized.
    assert_eq!(ip4i::get_proto_name(6), "witness_proto");
}
