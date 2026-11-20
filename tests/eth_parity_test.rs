//! Parity test for the row-18d codecs link-layer port — 4 ground TUs
//! (root/cd_eth.cc 262 + codec_module.h 269 + codec_module.cc 71 +
//! link/cd_arp.cc 128 = 730 L, every wc re-measured in eth PLAN §0).
//!
//! Ground truth #1: `tools/eth_harness/vectors.txt` (15 L NEVER
//! edited; md5 1bd98dbb57dd2f536104995bd76d9bad — the -O0 == -O2
//! byte-ident pair verified by the harness build.sh cmp arms, eth
//! PLAN §3). The WHOLE transcript replays HERE line-for-line as ONE
//! ordered session (the flog/fsvc/fmod/csum/vocab replay shape: per-
//! index assert_eq over want.len()==15 — ordered, never
//! set-membership). The probe's statement order == the transcript
//! order (probe.cc staged VERBATIM from the scratch main, eth PLAN
//! §3): eth api/help/decode-ladder/DLT-ladder/PIDS, then the arp
//! pair, then the CodecModule MOD line.
//!
//! Ground truth #2: there is NO upstream suite to translate — the §0
//! census measured 0 TEST_CASE / 0 TEST( / 0 UNIT_TEST on ALL FOUR
//! row files (eth PLAN §0, build.sh grep asserts, and the same
//! 0/0/0 table in NEXT.md:231-:237), and the CppUTest suites that
//! #include row siblings cannot build on this host (the E4 multi-
//! wall receipts the build.sh re-proves every build,
//! E4_cpputest_fatal.txt). So this row honestly ships ZERO up_gate_*
//! mirrors — the absence itself is the artifact, recorded in
//! deviations row 18d with the suite-census cite. The second artifact
//! = the per-file arms below, every value cited to its vectors line
//! or its ground C lines (no blind fixtures; the port-by-reading
//! arms — cd_eth log/encode/format/update and cd_arp
//! get_protocol_ids, vectors-silent per eth PLAN §3 — assert ONLY
//! against values the C source itself pins).
//!
//! Eval-order note (eth PLAN §3 R6): the frozen vectors pin the var-
//! first posture (every probe decode stored to a bool VAR before its
//! printf reads post-decode fields — probe.cc grep-pinned, 0
//! interleaves). The replay mirrors the EMITTED order: every EV line
//! lands between the decode call and its summary line exactly as the
//! C witness printf interleave does.

use snort3::codecs::cd_arp as arpc;
use snort3::codecs::cd_eth as ethc;
use snort3::codecs::cd_raw as rawc; // add_dlt ride (18c home)
use snort3::codecs::codec_module as cmod;
use snort3::framework::codec as fw;

const VECTORS: &str = include_str!("../tools/eth_harness/vectors.txt");

/// probe.cc:15 `uint8_t pkt[64]={0};` — one 64-byte buffer reused
/// ACROSS all arms (provenance matters for the encode-formatted
/// faces below: the probe mutates only bytes 12/13 between arms and
/// the ARP arms read len only). Verbatim posture.
fn pkt64() -> [u8; 64] {
    [0u8; 64]
}

// ==========================================================================
// 1. Whole-transcript replay — vectors.txt 15 lines, ordered, one
//    session (probe.cc statement order).
// ==========================================================================
#[test]
fn eth_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 15, "vectors.txt must hold the full 15-line ladder");

    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };

    // the queue_event witness seam: `EV %u %u\n` (stubs_18d.cc
    // DetectionEngine::queue_event — the harness witness body; the
    // gid is the ORIGINAL constexpr GID_DECODE 116 from
    // codec_module.h:38 used verbatim by the REAL framework/codec.cc
    // codec_event, eth PLAN §2).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };

    // -- probe.cc:9 `const CodecApi* ea = (const CodecApi*)cd_eth[0];`
    //    vectors:1-2 come from the ETH_API record readbacks.
    let ea = ethc::CD_ETH[0];
    push(format!(
        "API eth type={} size={} ver={} name={}",
        ea.ptype, ea.size, ea.api_version, ea.name
    )); // vectors:1
    assert_eq!(ea.ptype, 0); // vectors:1 `type=0` = PT_CODEC (base_api.h:52 enum head)
    push(format!("HELP {}", ea.help)); // vectors:2 HELP ladder face

    //    probe.cc:13 `Codec* eth = ea->ctor(nullptr);` — the SET ctor
    //    slot (ETH_API ctor=true mirrors cc:249), mirrored by the
    //    landed type:
    let eth = ethc::EthCodec::new();

    //    probe.cc:16-17 arm 1: RawData r0(pkt, 12); decode -> false.
    //    Fresh CodecData per arm (CodecData cd0(&conf, ETHERTYPE_
    //    NOT_SET)), fresh DecodeData (never read). R6: bool a stored
    //    to a VAR first, then one printf. vectors:3/:4.
    let pkt = pkt64();
    {
        let raw = fw::RawData {
            data: &pkt,
            len: 12,
        };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::ETHERTYPE_NOT_SET);
        let a = eth.decode(&raw, &mut cd, &mut sink); // raises EV 116 424
        push(format!("ETH short -> {}", a as i32)); // vectors:4 `ETH short -> 0`
    }

    //    probe.cc:18-22 arm 2: pkt[12]=0x08; pkt[13]=0x00 (an
    //    ETHERTYPE_IPV4 ethertype on the wire); len 14. vectors:5
    //    `ETH v4 -> 1 next=2048 lyr=14 bits=2048`.
    let mut pkt = pkt;
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    {
        let raw = fw::RawData {
            data: &pkt,
            len: 14,
        };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::ETHERTYPE_NOT_SET);
        let b = eth.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "ETH v4 -> {} next={} lyr={} bits={}",
            b as i32, cd.next_prot_id, cd.lyr_len, cd.proto_bits // dec posture: 2048 = 0x0800 both, vec:5
        ));
    }

    //    probe.cc:23-26 arm 3: pkt[12]=0x00; pkt[13]=0x05 — the
    //    `<= ETHERTYPE_MINIMUM` (0x0600) LLC arm. vectors:6 `ETH llc
    //    -> 1 next=263`.
    pkt[12] = 0x00;
    pkt[13] = 0x05;
    {
        let raw = fw::RawData {
            data: &pkt,
            len: 14,
        };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::ETHERTYPE_NOT_SET);
        let c = eth.decode(&raw, &mut cd, &mut sink);
        push(format!("ETH llc -> {} next={}", c as i32, cd.next_prot_id));
    }

    //    probe.cc:27-28 get_data_link_type + the DLT arms. vectors:
    //    7 `DLT 51` THEN 8 `DLT 1` — the push order cc:76-:77
    //    (PPP_ETHER FIRST), the inverse of the HELP-nesting cc:38.
    let mut dv: Vec<i32> = Vec::new();
    eth.get_data_link_type(&mut dv);
    for d in dv {
        push(format!("DLT {d}"));
    }

    //    probe.cc:29-30 get_protocol_ids. vectors:9 `PIDS 261 n=1`
    //    (ETHERNET_802_3 0x0105 = 261, protocol_ids.h:132).
    let mut pv: Vec<u16> = Vec::new();
    eth.get_protocol_ids(&mut pv);
    push(format!("PIDS {} n={}", pv[0], pv.len()));

    // -- probe.cc:31-33 the arp API face: the SHORT printf (name
    //    only) + HELPARP (NO DLT suffix — cc:32 plain, the contrast
    //    arm pinning the ladder as per-codec). vectors:11/:12.
    let aa = arpc::CD_ARP[0];
    push(format!("API arp name={}", aa.name));
    push(format!("HELPARP {}", aa.help));

    //    probe.cc:34 `Codec* arp = aa->ctor(nullptr);`
    let arp = arpc::ArpCodec::new();

    //    probe.cc:35-36 ARP short arm: same mutated pkt (bytes 12/13
    //    == 00 05; len 27 < 28). The arp decode NEVER reads contents
    //    (cc:67-:79 = pure length gate). vectors:12 `EV 116 109`
    //    (LITERAL, codec_module.h:73) then :13 `ARP short -> 0`.
    {
        let raw = fw::RawData {
            data: &pkt,
            len: 27,
        };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::ETHERTYPE_NOT_SET);
        let d = arp.decode(&raw, &mut cd, &mut sink);
        push(format!("ARP short -> {}", d as i32));
    }

    //    probe.cc:37-38 ARP ok arm: len 28 == ETHERARP_HDR_LEN
    //    (arp.h:50; NOT a size_of — the C /* sizeof EtherARP != 28 */
    //    comment kept at cd_arp.rs). vectors:14 `ARP ok -> 1 lyr=28
    //    bits=4194304` — 4194304 == PROTO_BIT__ARP 0x400000
    //    (decode_data.h:109, all-decimal posture); next_prot_id
    //    STAYS the init ETHERTYPE_NOT_SET (no next= in the line).
    {
        let raw = fw::RawData {
            data: &pkt,
            len: 28,
        };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::ETHERTYPE_NOT_SET);
        let e = arp.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "ARP ok -> {} lyr={} bits={}",
            e as i32, cd.lyr_len, cd.proto_bits
        ));
    }

    // -- probe.cc:39-41 `CodecModule m;` + rules walk + the MOD
    //    line. vectors:15 `MOD rules=8 gid=116 help=general decoder
    //    rules trace=null`: rules=8 = the while(rm[n].sid) n++ walk
    //    of the cc:55-:67 8-row general_decode_rules stopping at the
    //    cc:66 terminator; gid=116 = the h:38 GID_DECODE via
    //    h:249-:250; help = cc:30-:31; trace=null = the cc:47-:48
    //    `#ifndef DEBUG_MSGS` nullptr arm (eth PLAN §3, seam note
    //    in codec_module.rs).
    let m = cmod::CodecModule::new();
    let n = cmod::rule_count(m.get_rules());
    push(format!(
        "MOD rules={} gid={} help={} trace={}",
        n,
        m.get_gid(),
        m.get_help(),
        if m.get_trace_options().is_some() { "on" } else { "null" }
    ));

    let got = out.borrow().clone();
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "transcript line {} diverged", i + 1);
    }
    assert_eq!(got.len(), want.len(), "transcript line count");
}

// ==========================================================================
// Per-file arms (ground truth #2; zero-suite row = no up_gate_* set,
// the honest absence pinned in the module header + deviations row
// 18d). EVERY value cites its vectors line or its ground C line.
// ==========================================================================

/// codec_module.h:44-:234 the enum walk — the comment-anchor pins
/// (`// = 430` h:183, `// = 440` h:193, `// = 450` h:203, `// = 460`
/// h:213, `// = 470` h:223) MUST match the walked discriminants, and
/// the two vectors-pinned sids with them: DECODE_ETH_HDR_TRUNC = 424
/// by WALK (418 h:171 + six h:172-:176 -> h:177; vectors:3
/// `EV 116 424`) vs DECODE_ARP_TRUNCATED = 109 by LITERAL (h:73;
/// vectors:13 `EV 116 109`) — the double-pin discipline (eth §3).
#[test]
fn codec_sid_walk_vs_header() {
    use cmod::CodecSid as S;
    // explicit-`=` anchors straight from the C source
    assert_eq!(S::DECODE_NOT_IPV4_DGRAM as u32, 1); // h:46 `= 1`
    assert_eq!(S::DECODE_ICMP4_TYPE_OTHER as u32, 418); // h:171 `= 418`
    assert_eq!(S::DECODE_ARP_TRUNCATED as u32, 109); // h:73 `= 109` LITERAL pin
    // trailing-comment anchors (the walk-vs-comment agreement)
    assert_eq!(S::DECODE_IP4_DF_OFFSET as u32, 430); // h:183 `// = 430`
    assert_eq!(S::DECODE_ICMP_BROADSCAN_SMURF_SCANNER as u32, 440); // h:193 `// = 440`
    assert_eq!(S::DECODE_IP_BAD_PROTO as u32, 450); // h:203 `// = 450` (18c vectors vocab:9 pair)
    assert_eq!(S::DECODE_IP6_EXCESS_EXT_HDR as u32, 456); // h:209 walk (18c vocab vectors:16)
    assert_eq!(S::DECODE_ICMPV6_NODE_INFO_BAD_CODE as u32, 460); // h:213 `// = 460`
    assert_eq!(S::DECODE_CISCO_META_HDR_OPT_TYPE as u32, 470); // h:223 `// = 470`
    // walk products THIS row leans on
    assert_eq!(S::DECODE_ETH_HDR_TRUNC as u32, 424); // h:177 — vectors:3
    assert_eq!(S::DECODE_ZERO_LENGTH_FRAG as u32, 459); // h:212 (GENERAL_DECODE_RULES row 3)
    assert_eq!(S::DECODE_IP_UNASSIGNED_PROTO as u32, 449); // h:202 (row 6)
    assert_eq!(S::DECODE_TOO_MANY_LAYERS as u32, 472); // h:225 (row 7)
    assert_eq!(S::DECODE_BAD_ETHER_TYPE as u32, 473); // h:226 (row 8)
    assert_eq!(S::DECODE_INDEX_MAX as u32, 480); // h:233 enum tail marker
    // the 170-entry census itself: FIRST..LAST span the walk; the
    // harness-side C++ header printed the same via the 424 EV probe.
    assert_eq!(S::DECODE_INDEX_MAX as u32 - S::DECODE_NOT_IPV4_DGRAM as u32, 479);
}

/// codec_module.cc general_decode_rules: the 8-row walk count the
/// probe pins (`rules=8` vectors:15) + the ORDER + the msg strings —
/// every msg byte-exact from cc:57-:65 (the two-line cc:58-:59 entry
/// is ONE string). The sids come from the walk above, never typed.
#[test]
fn general_decode_rules_table() {
    let t = cmod::general_decode_rules();
    assert_eq!(cmod::rule_count(t), 8, "vectors:15 `rules=8`");
    assert_eq!(t.len(), 9, "8 rows + the cc:66 terminator");
    let want: [(u32, &str); 8] = [
        (450, "bad IP protocol"), // cc:57 (h:203 `// = 450`)
        (
            293,
            "two or more IP (v4 and/or v6) encapsulation layers present",
        ), // cc:58-:59 (h:145 `= 293`)
        (459, "fragment with zero length"), // cc:60 (h:212 walk)
        (150, "loopback IP"),               // cc:61 (h:90 `= 150`)
        (151, "same src/dst IP"),           // cc:62 (h:91 `= 151`)
        (449, "unassigned/reserved IP protocol"), // cc:63 (h:202 walk)
        (472, "too many protocols present"),      // cc:64 (h:225 walk)
        (473, "ether type out of range"),         // cc:65 (h:226 walk)
    ];
    let cc_rows = [57usize, 58, 60, 61, 62, 63, 64, 65]; // the C table lines (cc:58-:59 = one entry)
    for (i, (sid, msg)) in want.iter().enumerate() {
        assert_eq!(t[i].sid, *sid, "general_decode_rules row {i} sid (cc:{})", cc_rows[i]);
        assert_eq!(t[i].msg, Some(*msg), "general_decode_rules row {i} msg");
    }
    // cc:66 `{ 0, nullptr }` — the walk-stop sentinel; msg NEVER read
    // (the rule_count loop stops on sid==0 first, h/module.cc idiom).
    assert_eq!(t[8].sid, 0);
    assert_eq!(t[8].msg, None);
}

/// codec_module face reads the MOD line's other three fields: name
/// `"decode"` (cc:33 s_name — NOT a cd_* name), help `"general
/// decoder rules"` (cc:30-:31; vectors:15), gid 116 (h:38 via
/// h:249-:250 via vectors:15) — plus the cc:37 s_params ONE-entry
/// terminator table (name nullptr, PT_MAX, deflt nullptr) and the
/// BaseCodecModule ctor arm h:246-:247 defaulting is_list=false.
#[test]
fn codec_module_record_face() {
    let m = cmod::CodecModule::new();
    assert_eq!(m.get_name(), "decode"); // cc:33
    assert_eq!(m.get_help(), "general decoder rules"); // cc:31; vectors:15
    assert_eq!(m.get_gid(), 116); // h:38 GID_DECODE; vectors:15
    assert_eq!(m.base.get_usage(), cmod::C_USAGE_CONTEXT); // h:253-:254 CONTEXT (= 1, module.h:216 order)
    // h:246 is_list default false; params = the cc:37 one-row table
    assert!(!m.base.is_list);
    let p = m.base.params.expect("3-arg ctor sets s_params (cc:39)");
    assert_eq!(p.len(), 1, "cc:37 ONE-entry table");
    assert_eq!(p[0].name, None); // `{ nullptr, ... }`
    assert_eq!(p[0].ptype, snort3::framework::parameter::Type::PtMax); // Parameter::PT_MAX
    assert_eq!(p[0].deflt, None); // 4th field nullptr
    // cc:47-:48 nullptr trace-options arm — vectors:15 `trace=null`
    assert_eq!(m.get_trace_options(), None);
}

/// codec_module.cc lines 34-35 and 42-43: the decode_trace THREAD_LOCAL
/// slot plus the set_trace write, riding the landed 18a TraceToken
/// posture (file_module.rs:112-:129 twin). vectors:15 shows only the
/// null face; the arm sequence mirrors what the slot can observe.
static TK: cmod::TraceToken = cmod::TraceToken;

#[test]
fn decode_trace_slot_face() {
    let m = cmod::CodecModule::new();
    assert!(!cmod::CodecModule::decode_trace_armed()); // cc:35 `= nullptr` NSDMI (fresh test thread)
    m.set_trace(Some(&TK)); // cc:43 `decode_trace = trace;`
    assert!(cmod::CodecModule::decode_trace_armed());
    m.set_trace(None); // the 18a V3 null-after-arm twin
    assert!(!cmod::CodecModule::decode_trace_armed());
}

/// cd_eth HELP ladder consistency (vectors:2 `support for ethernet
/// protocol (DLT 1) (DLT 51)`): re-compose the cc:38 nesting
/// `ADD_DLT(ADD_DLT(s, DLT_EN10MB), DLT_PPP_ETHER)` with the 18c
/// add_dlt fn (cd_raw.rs:48-:50) over the 18d graft values (DLT_EN10MB
/// 1 = libpcap master dlt.h:68, DLT_PPP_ETHER 51 = master :243, eth
/// PLAN §1) — the literal can never drift from the graft consts. Also
/// pins the push-order CONTRAST (cc:38 outer PPP_ETHER vs cc:76-:77
/// PPP_ETHER-first emplace — both faces pinned independently).
#[test]
fn eth_dlt_ladder_composition() {
    let composed = rawc::add_dlt(
        &rawc::add_dlt(ethc::CD_ETH_HELP_STR, ethc::DLT_EN10MB),
        ethc::DLT_PPP_ETHER,
    );
    assert_eq!(composed, ethc::CD_ETH_HELP); // vectors:2 face
    assert_eq!(ethc::DLT_EN10MB, 1); // master dlt.h:68
    assert_eq!(ethc::DLT_PPP_ETHER, 51); // master dlt.h:243
}

/// cd_eth decode FabricPath arm (cc:103-:112) — the ONLY arm without
/// the proto_bits OR (operand identity per arm, literal-transcription
/// discipline). Vectors silent (eth PLAN §3); values from the C arm
/// itself: next = raw ethertype (0x8903 = 35075), lyr_len = 0,
/// proto_bits UNTOUCHED. Cites cc:110 (next) / cc:111 (lyr_len).
#[test]
fn eth_fpath_decode_arm() {
    let mut pkt = pkt64();
    pkt[12] = 0x89;
    pkt[13] = 0x03; // ETHERTYPE_FPATH 0x8903, protocol_ids.h:160
    let raw = fw::RawData {
        data: &pkt,
        len: 14,
    };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::ETHERTYPE_NOT_SET);
    let ev = std::cell::Cell::new(0usize);
    let mut sink = |_, _| ev.set(ev.get() + 1);
    let ok = ethc::EthCodec::new().decode(&raw, &mut cd, &mut sink);
    assert!(ok); // cc:120
    assert_eq!(ev.get(), 0, "no event on the fpath arm");
    assert_eq!(cd.next_prot_id, 0x8903); // cc:110 (35075 decimal posture)
    assert_eq!(cd.lyr_len, 0); // cc:111
    assert_eq!(cd.proto_bits, 0); // the arm DOES NOT set PROTO_BIT__ETH
}

/// EthCodec::log arms (cc:123-:136), port-by-reading (probe never
/// calls log): the cc:132-:135 reprint of the <= ETHERTYPE_MINIMUM
/// test with the format strings byte-exact — `"  len:0x%04X"`
/// (cc:133, two leading spaces + %04X upper) vs `"  type:0x%04X"`
/// (cc:135).
#[test]
fn eth_log_arms() {
    let mut lines: Vec<String> = Vec::new();
    {
        let mut sink = |s: String| lines.push(s);
        let mut pkt = pkt64();
        pkt[12] = 0x00;
        pkt[13] = 0x05; // <= 0x0600 -> the len: face (cc:133)
        ethc::EthCodec::new().log(&mut sink, &pkt);
        pkt[12] = 0x08;
        pkt[13] = 0x00; // -> the type: face (cc:135)
        ethc::EthCodec::new().log(&mut sink, &pkt);
    }
    assert_eq!(lines[0], "  len:0x0005");
    assert_eq!(lines[1], "  type:0x0800");
}

/// EthCodec::encode (cc:142-:189), port-by-reading. Five faces:
/// fpath ethertype -> early true, NO allocation (cc:147-:148);
/// fwd + null eth_dst -> src<-hi src (cc:168), dst<-hi dst (cc:173);
/// fwd + set eth_dst -> dst<-sc eth_dst (cc:170-:171);
/// reverse + null eth_dst -> src<-hi DST (cc:177), dst<-hi SRC
/// (cc:182) — the swap the format() twin also encodes; and
/// next_ethertype SET -> ho->ether_type = htons(to_utype(...)) —
/// the cc:161-:162 TERNARY precedence: htons applies ONLY to that
/// arm, the else-arm copies the RAW wire u16, never double-swapped.
/// The Buffer allocate arms cc:157-:158 ride the landed Buffer.
#[test]
fn eth_encode_arms() {
    let hi: [u8; 14] = {
        let mut p = [0u8; 14];
        p[0..6].copy_from_slice(&[0xd1; 6]); // ether_dst (eth.h:40)
        p[6..12].copy_from_slice(&[0x51; 6]); // ether_src (eth.h:41-:42)
        p[12] = 0x08;
        p[13] = 0x00; // ETHERTYPE_IPV4
        p
    };

    // face 1: fpath -> true, no allocate (buf.size() stays 0)
    {
        let mut fp = hi;
        fp[12] = 0x89;
        fp[13] = 0x03;
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        assert!(ethc::EthCodec::new().encode(&fp, 14, &mut enc, &mut buf, None));
        assert_eq!(buf.size(), 0, "cc:148 early return, no allocate");
    }

    // face 2: fwd, conf None (eth_dst nullptr, the WITNESS-MEASURABLE
    // arm, eth PLAN §2): dst<-hi dst, src<-hi src.
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        assert!(ethc::EthCodec::new().encode(&hi, 14, &mut enc, &mut buf, None));
        let ho = buf.data().unwrap();
        assert_eq!(&ho[0..6], &[0xd1; 6]); // cc:173
        assert_eq!(&ho[6..12], &[0x51; 6]); // cc:168
        assert_eq!(&ho[12..14], &[0x08, 0x00]); // cc:162 raw copy (ethertype_set false)
        assert_eq!(enc.next_ethertype, 0); // cc:186 reset
        assert_eq!(enc.next_proto, 255); // cc:187 PROTO_NOT_SET
    }

    // face 3: fwd + set eth_dst (cc:170-:171) — sc.eth_dst Some
    {
        let mut sc = snort3::parser::parse_conf::SnortConfig::default();
        sc.eth_dst = Some([0xEE; 6]); // snort_config.h:289 set face
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        assert!(ethc::EthCodec::new().encode(&hi, 14, &mut enc, &mut buf, Some(&sc)));
        let ho = buf.data().unwrap();
        assert_eq!(&ho[0..6], &[0xEE; 6]); // cc:171
        assert_eq!(&ho[6..12], &[0x51; 6]); // cc:168
    }

    // face 4: reverse (no ENC_FLAG_FWD) + null eth_dst: the CROSS
    // copy — src<-hi DST, dst<-hi SRC (cc:177/:182).
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0);
        assert!(ethc::EthCodec::new().encode(&hi, 14, &mut enc, &mut buf, None));
        let ho = buf.data().unwrap();
        assert_eq!(&ho[0..6], &[0x51; 6]); // cc:182 dst<-hi src
        assert_eq!(&ho[6..12], &[0xd1; 6]); // cc:177 src<-hi dst
    }

    // face 5: enc.next_ethertype SET -> the htons arm (cc:161): BE
    // store of the host value. 0x1234 -> wire bytes 0x12,0x34.
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        enc.next_ethertype = 0x1234; // enc.ethertype_set() true (codec.rs:284-:286)
        assert!(ethc::EthCodec::new().encode(&hi, 14, &mut enc, &mut buf, None));
        let ho = buf.data().unwrap();
        assert_eq!(&ho[12..14], &[0x12, 0x34]); // htons(to_utype(next_ethertype))
        assert_eq!(enc.next_ethertype, 0); // cc:186 reset AFTER the store
    }

    // allocate-fail arm (cc:157-:158): tiny buffer, size==0 so the
    // `!raw` gate is entered raw=false; max_len 13 < 14 -> false.
    {
        let mut store = [0u8; 14];
        let mut buf = fw::Buffer::new(&mut store, 13);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        assert!(!ethc::EthCodec::new().encode(&hi, 14, &mut enc, &mut buf, None));
    }
}

/// EthCodec::format (cc:191-:204), port-by-reading: the reverse &&
/// !fpath swap ladder via the 6-byte tmp (cc:198-:202 ORDER:
/// tmp<-dst, dst<-src, src<-tmp); reverse+fpath NO swap (cc:196
/// guard); !reverse NO swap.
#[test]
fn eth_format_swap() {
    let mk = || {
        let mut p = [0u8; 14];
        p[0..6].copy_from_slice(&[0xd1; 6]);
        p[6..12].copy_from_slice(&[0x51; 6]);
        p[12] = 0x08;
        p[13] = 0x00;
        p
    };
    // reverse + normal -> swap
    let mut p = mk();
    ethc::EthCodec::new().format(true, &mut p);
    assert_eq!(&p[0..6], &[0x51; 6]);
    assert_eq!(&p[6..12], &[0xd1; 6]);
    assert_eq!(&p[12..14], &[0x08, 0x00]); // ethertype untouched
    // reverse + fpath -> NO swap (cc:196 guard)
    let mut f = mk();
    f[12] = 0x89;
    f[13] = 0x03;
    ethc::EthCodec::new().format(true, &mut f);
    assert_eq!(&f[0..6], &[0xd1; 6]);
    assert_eq!(&f[6..12], &[0x51; 6]);
    // !reverse -> NO swap regardless
    let mut p2 = mk();
    ethc::EthCodec::new().format(false, &mut p2);
    assert_eq!(&p2[0..6], &[0xd1; 6]);
}

/// EthCodec::update (cc:206-:213), port-by-reading: `updated_len +=
/// lyr_len` on every NON-fpath ethertype (cc:212), fpath SKIPS it —
/// the guard reads the ethertype, not the flags.
#[test]
fn eth_update_arm() {
    let mk = |et: [u8; 2]| {
        let mut p = [0u8; 14];
        p[12] = et[0];
        p[13] = et[1];
        p
    };
    let mut upd = 100u32;
    ethc::EthCodec::new().update(&mk([0x08, 0x00]), 14, &mut upd);
    assert_eq!(upd, 114); // cc:212 += lyr_len
    ethc::EthCodec::new().update(&mk([0x89, 0x03]), 14, &mut upd);
    assert_eq!(upd, 114); // fpath arm skips the += (cc:211 guard)
}

/// cd_arp get_protocol_ids (cc:61-:65), port-by-reading (probe never
/// calls it — no ARP PIDS line in vectors): the emplace ORDER
/// ETHERTYPE_ARP 0x0806 then ETHERTYPE_REVARP 0x8035
/// (protocol_ids.h:145/:148).
#[test]
fn arp_get_protocol_ids_order() {
    let mut pv: Vec<u16> = Vec::new();
    arpc::ArpCodec::new().get_protocol_ids(&mut pv);
    assert_eq!(pv.len(), 2, "two emplace_backs (cc:63/cc:64)");
    assert_eq!(pv[0], 0x0806); // cc:63
    assert_eq!(pv[1], 0x8035); // cc:64
}

/// cd_arp record + table face: the vectors-pinned API/HELPARP parts
/// (vectors:11 `API arp name=arp`, vectors:12 the NO-DLT-suffix
/// HELP) plus the record slots the probe readback CANNOT see but the
/// C init list pins literally (cc:100-:116): the Module pair SET
/// (cc:108-:109, the EthModule/ArpModule news contrast vs the four
/// nullptr-module 18c records), aux four nullptr (cc:111-:114), ctor/
/// dtor SET (cc:115-:116), features PLUGIN_SO_RELOAD (cc:104),
/// size == the 112 probe pin, version 0 (cc:103). The eth record
/// carries the identical census at cc:234-:250 + the module pair SET
/// (cc:242-:243) — asserted together as the two-TU table face.
#[test]
fn eth_arp_record_census() {
    for (api, name, help) in [
        (ethc::ETH_API, "eth", "support for ethernet protocol (DLT 1) (DLT 51)"), // vectors:1/:2
        (arpc::ARP_API, "arp", "support for address resolution protocol"), // vectors:11/:12 (no DLT suffix, cc:32)
    ] {
        assert_eq!(api.ptype, 0); // PT_CODEC, vectors:1 type=0
        assert_eq!(api.size, 112); // vectors:1 size=112 (PROBE pin, codec.rs:405)
        assert_eq!(api.api_version, 1_900_547); // (29<<16)|3, vectors:1 ver=
        assert_eq!(api.version, 0); // cd_eth.cc:237 / cd_arp.cc:103
        assert_eq!(api.features, 1); // PLUGIN_SO_RELOAD, cc:238/cc:104
        assert_eq!(api.name, name);
        assert_eq!(api.help, help);
        assert!(api.mod_ctor && api.mod_dtor); // cc:242-:243 / cc:108-:109 SET
        assert!(!(api.pinit || api.pterm || api.tinit || api.tterm)); // cc:245-:248 / cc:111-:114 nullptr
        assert!(api.ctor && api.dtor); // cc:249-:250 / cc:115-:116 SET
    }
    // the exported tables: one entry each (probe.cc:9/:31 `cd_x[0]`),
    // the null-terminator folded onto the slice len (deviations row
    // 18c posture KEPT); eth PLAN §5: 18d's REAL cd_arp/cd_eth collide
    // with NO vocab stub (witness_stubs.cc carries no cd_arp/cd_eth).
    assert_eq!(ethc::CD_ETH.len(), 1);
    assert_eq!(arpc::CD_ARP.len(), 1);
    // rule tables: one row each + terminator (cc:42-:46 / cc:36-:40)
    assert_eq!(ethc::EthModule::get_rules()[0], (424, "truncated ethernet header"));
    assert_eq!(ethc::EthModule::get_rules()[1], (0, ""));
    assert_eq!(arpc::ArpModule::get_rules()[0], (109, "truncated ARP"));
    assert_eq!(arpc::ArpModule::get_rules()[1], (0, ""));
    // cd_eth.cc decode-gate constant (eth.h:37) vs cd_arp's (arp.h:50
    // — /* sizeof EtherARP != 28 */: the gate is the LITERAL pin):
    assert_eq!(ethc::ETH_HEADER_LEN, 14);
    assert_eq!(arpc::ETHERARP_HDR_LEN, 28);
}
