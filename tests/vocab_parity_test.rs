//! Parity test for the row-18c codecs-vocabulary port — 5 ground TUs
//! (codec_api.{h,cc} + misc/cd_default.cc + ip/cd_bad_proto.cc +
//! ip/cd_no_next.cc + root/cd_raw.cc = 549 L).
//!
//! Ground truth #1: `tools/vocab_harness/vectors.txt` (29 L NEVER
//! edited; md5 5da70e82416b6f769af8177d859331e7 — the -O0 == -O2
//! byte-ident pair, vocab PLAN §3). The WHOLE transcript replays HERE
//! line-for-line as ONE ordered session (the flog/fsvc/fmod/csum
//! replay shape: per-index assert_eq over want.len()==29 — ordered,
//! never set-membership). The probe's statement order == the C TU
//! order: four exported tables iterated (probe.cc:37-:86) then
//! load_codecs() (probe.cc:87-:88).
//!
//! Ground truth #2: there is NO upstream suite to translate — the §0
//! census measured 0 TEST_CASE / 0 TEST( / 0 UNIT_TEST on all six row
//! files (vocab PLAN §0), and the CppUTest suites that #include row
//! siblings are unbuildable on this host (the E4 two-wall receipt the
//! build.sh re-proves every build). So the second artifact per the
//! PORTING ritual here = per-file arms below, every value cited to a
//! vectors line (no blind fixtures; unverifiable-fixture rule).
//!
//! Eval-order note (PLAN §3 R6): C printf arg evaluation interleaves
//! side effects — the frozen vectors pin the var-first posture (raw
//! v4/v6 arms store `bool r` before printf, probe.cc:61-:65). The
//! replay mirrors the EMITTED order: every EV line lands between the
//! decode call and its DECODE/NN line exactly as the probe order does.

use snort3::codecs::cd_bad_proto as badproto;
use snort3::codecs::cd_default as cdef;
use snort3::codecs::cd_no_next as nonext;
use snort3::codecs::cd_raw as rawcodec;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/vocab_harness/vectors.txt");

/// probe.cc:53 `uint8_t buf[64] = { 0x45,0,0,0, 0x60,0,0,0 };` —
/// verbatim literal (64 bytes; the eight show, the rest init 0 like C).
fn buf64() -> [u8; 64] {
    let mut b = [0u8; 64];
    b[0] = 0x45;
    b[4] = 0x60;
    b
}

// ==========================================================================
// 1. Whole-transcript replay — vectors.txt 29 lines, ordered, one
//    session (probe.cc statement order).
// ==========================================================================
#[test]
fn vocab_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 29, "vectors.txt must hold the full 29-line ladder");
    // Rc<RefCell<Vec<String>>> transcript: the queue_event sink closure
    // lives across the whole session (the C witness printf goes to the
    // same stdout the driver writes) -- the landed WitnessOut shape
    // (file_inspect.rs:113).
    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };

    // the queue_event witness seam: 'EV gid sid' (framework/codec.cc:85
    // REAL home linked by the harness -- PLAN §2 nm census RESOLVED).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };

    // probe.cc:37 -- the four EXPORTED tables, the probe's literal list
    // order (default, bad_proto, no_next, raw).
    let tables: [fw::CodecTable; 4] = [
        cdef::CD_DEFAULT,
        badproto::CD_BAD_PROTO,
        nonext::CD_NO_NEXT,
        rawcodec::CD_RAW,
    ];

    for t in tables {
        let api = t[0];
        // probe.cc:41-:44 API %s type=%d size=%u ver=%u features=%llx name=%s
        push(format!(
            "API {} type={} size={} ver={} features={} name={}",
            api.name, api.ptype, api.size, api.api_version, api.features, api.name
        ));

        // probe.cc:45 `Codec* c = api->ctor(nullptr);` -- per-name ctor
        // per the probe's later strcmp dispatch: the Rust ctor arms.
        let mut ids: Vec<fw::ProtocolId> = Vec::new();
        let mut dlts: Vec<i32> = Vec::new();
        match api.name {
            "unknown" => cdef::DefaultCodec::new().get_protocol_ids(&mut ids),
            "bad_proto" => badproto::BadProtocalCodec::new().get_protocol_ids(&mut ids),
            "ipv6_no_next" => nonext::Ipv6NoNextCodec::new().get_protocol_ids(&mut ids),
            "raw" => rawcodec::RawCodec::new().get_data_link_type(&mut dlts),
            _ => unreachable!("row vocabulary has exactly four names"),
        }
        // probe.cc:46-:49 PID/DLT loops (raw answers DLT then NO PID --
        // no get_protocol_ids override, the base's empty vector).
        for id in &ids {
            push(format!("PID {id}"));
        }
        for d in &dlts {
            push(format!("DLT {d}"));
        }
        // probe.cc:50 HELP %s
        push(format!("HELP {}", api.help));

        // probe.cc:52 SnortConfig conf (default-constructed per table).
        let conf = SnortConfig::default();
        let b64 = buf64();

        if api.name == "unknown" {
            // probe.cc:55-:57: raw len 16 over buf[64]; decode -> false.
            let raw = fw::RawData { data: &b64, len: 16 };
            let _cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
            let r = cdef::DefaultCodec::new().decode(); // cc:41-:42 (no params read)
            push(format!("DECODE unknown -> {}", r as i32));
            let _ = raw;
        }
        if api.name == "raw" {
            // probe.cc:59-:67: three 1-byte arms; the v4/v6 arms store
            // `bool r` BEFORE the two-field printf (R6 eval-order rule).
            {
                let b = [0x45u8; 1];
                let raw = fw::RawData { data: &b, len: 1 };
                let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
                let r = rawcodec::RawCodec::new().decode(&raw, &mut cd); // cc:46
                push(format!("DECODE raw v4 -> {} next={}", r as i32, cd.next_prot_id));
            }
            {
                let b = [0x60u8; 1];
                let r6 = fw::RawData { data: &b, len: 1 };
                let mut cd6 = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
                let r = rawcodec::RawCodec::new().decode(&r6, &mut cd6);
                push(format!("DECODE raw v6 -> {} next={}", r as i32, cd6.next_prot_id));
            }
            {
                let b = [0x50u8; 1];
                let rx = fw::RawData { data: &b, len: 1 };
                let mut cdx = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
                let r = rawcodec::RawCodec::new().decode(&rx, &mut cdx);
                push(format!("DECODE raw bad -> {}", r as i32));
            }
        }
        if api.name == "bad_proto" {
            // probe.cc:69-:72: printf("%d", c->decode(...)) -- the decode
            // FULLY runs (the EV witness line lands) before printf prints.
            // _raw keeps the probe's cc-fixture statement (probe.cc:70);
            // the ported arm reads neither RawData nor DecodeData (the
            // C params are unnamed — see cd_bad_proto.rs decode cite).
            let _raw = fw::RawData { data: &b64, len: 16 };
            let cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
            let r = badproto::BadProtocalCodec::new().decode(&cd, &mut sink); // EV lands here
            push(format!("DECODE bad_proto -> {}", r as i32));
        }
        if api.name == "ipv6_no_next" {
            // probe.cc:73-:84: three arms.
            {
                let raw = fw::RawData { data: &b64, len: 7 };
                let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
                let r = nonext::Ipv6NoNextCodec::new().decode(&raw, &mut cd, &mut sink);
                push(format!("NN short -> {}", r as i32));
            }
            {
                let raw = fw::RawData { data: &b64, len: 8 };
                let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
                // int r = decode(...) THEN the multi-field printf (R6).
                let r = nonext::Ipv6NoNextCodec::new().decode(&raw, &mut cd, &mut sink);
                push(format!(
                    "NN ok -> {} lyr={} bits={:x} cnt={}",
                    r as i32, cd.lyr_len, cd.proto_bits, cd.ip6_extension_count
                ));
            }
            {
                // probe.cc:80 conf.max_ip6_extensions = 2; THEN a FRESH
                // CodecData with ip6_extension_count = 2 pre-set (:82).
                let mut conf2 = SnortConfig::default();
                conf2.max_ip6_extensions = 2;
                let raw = fw::RawData { data: &b64, len: 8 };
                let mut cd = fw::CodecData::new(Some(&conf2), fw::protocol_id::ETHERTYPE_NOT_SET);
                cd.ip6_extension_count = 2;
                // EV lands here (vec 16), the print follows (vec 17).
                let r = nonext::Ipv6NoNextCodec::new().decode(&raw, &mut cd, &mut sink);
                push(format!("NN maxopts -> {}", r as i32));
            }
        }
        // probe.cc:85 api->dtor(c) -- no witness output.
    }

    // probe.cc:87-:88: load_codecs() then LOADS %d.
    let mut loads = 0usize;
    {
        let out2 = Rc::clone(&out);
        let mut lsink = |head: &'static fw::CodecApiRecord| {
            // probe.cc:28 witness body: printf("LOAD %s", plugins[0]->name)
            out2.borrow_mut().push(format!("LOAD {}", head.name));
            loads += 1;
        };
        capi::load_codecs(&mut lsink);
    }
    push(format!("LOADS {loads}"));

    let got = out.borrow();
    for (i, line) in got.iter().enumerate() {
        assert_eq!(line, want[i], "vectors line {} mismatch", i + 1);
    }
    assert_eq!(got.len(), 29, "the replay must emit exactly 29 lines");
}

// ==========================================================================
// 2. Per-file arms (no upstream suite this row — see header; every
//    value cites its vectors line).
// ==========================================================================

// ---- codec_api.rs ----

#[test]
/// cc:78-:82 LOAD order vs cc:31-:36 extern-declaration order: the
/// hopopts/tcp SWAP (PLAN pin). The sink order is what the frozen
/// vectors:24-:28 pin.
fn codec_api_load_order_pins_cc_call_order() {
    let mut names = Vec::new();
    {
        let mut sink: capi::LoadSink = &mut |head| names.push(head.name);
        capi::load_codecs(&mut sink);
    }
    assert_eq!(
        names,
        vec![
            "unknown",
            "cd_ipv4_stub",
            "cd_ipv6_stub",
            "cd_tcp_stub",
            "cd_hopopts_stub",
        ]
    ); // vectors:24-:28 order verbatim
    assert_eq!(names.len(), 5, "STATIC_CODECS arm must stay dormant"); // vectors:29 LOADS 5
}

#[test]
/// the STATIC_CODECS face (cc:39-:73): dormant const + the 34 extern
/// names cc-order verbatim — first/last + a few anchors; the vectors
/// LOADS-5 face proves the arm never compiled in.
fn codec_api_static_ladder_dormant_and_named() {
    // the vectors:29 (`LOADS 5`) face pins the dormancy; the assert is
    // the const pin made visible (clippy::assertions_on_constants is
    // intentional here: the value, once flipped by a later row, must
    // fail this test as a drift tripwire).
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(!capi::STATIC_CODECS);
    }
    assert_eq!(capi::STATIC_CODEC_EXTERN_NAMES.len(), 34); // cc:40-:73 count
    assert_eq!(capi::STATIC_CODEC_EXTERN_NAMES[0], "cd_ah"); // cc:40
    assert_eq!(capi::STATIC_CODEC_EXTERN_NAMES[2], "cd_bad_proto"); // cc:42
    assert_eq!(capi::STATIC_CODEC_EXTERN_NAMES[33], "cd_vxlan"); // cc:73
    // the row's own two STATIC-only TUs appear exactly once each:
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES
            .iter()
            .filter(|n| **n == "cd_no_next" || **n == "cd_raw")
            .count(),
        2
    );
}

// ---- misc/cd_default.rs ----

#[test]
/// vectors:1 `API unknown type=0 size=112 ver=1900547 features=0
/// name=unknown` — record face, then vectors:2 PID 256
/// (FINISHED_DECODE), vectors:3 HELP, vectors:4 `DECODE unknown -> 0`.
/// features=0 = API_RESERVED: cd_default is the ONE row codec WITHOUT
/// PLUGIN_SO_RELOAD.
fn cd_default_record_and_posture() {
    let a = cdef::DEFAULT_API;
    assert_eq!(a.ptype, 0); // PT_CODEC head (base_api.h:52)
    assert_eq!(a.size, 112); // probe pin (CDAPI_SIZEOF_CODEC_API)
    assert_eq!(a.api_version, 1_900_547); // (29<<16)|3 (codec.h:379)
    assert_eq!(a.features, 0); // API_RESERVED (cc:63) vectors:1
    assert_eq!(a.name, "unknown");
    assert_eq!(a.help, "support for unknown protocols"); // vectors:3
    let mut ids = Vec::new();
    cdef::DefaultCodec::new().get_protocol_ids(&mut ids);
    assert_eq!(ids, vec![0x0100]); // protocol_ids.h:127 -- vectors:2
    assert!(!cdef::DefaultCodec::new().decode()); // vectors:4
}

// ---- ip/cd_bad_proto.rs ----

#[test]
/// vectors:6/:7 PID 53 + PID 77 (SWIPE then SUN_ND, emplace order),
/// vectors:9/:10 `EV 116 450` then `DECODE bad_proto -> 1` — the
/// event-then-true posture, gid 116 = GID_DECODE, sid 450 =
/// DECODE_IP_BAD_PROTO (codec_module.h:203 comment-pinned).
fn cd_bad_proto_event_arm() {
    let mut ids = Vec::new();
    badproto::BadProtocalCodec::new().get_protocol_ids(&mut ids);
    assert_eq!(ids, vec![53, 77]); // vectors:6/:7 -- SWIPE then SUN_ND
    let conf = SnortConfig::default();
    let cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
    let mut ev: Vec<(u32, u32)> = Vec::new();
    let r = {
        let mut sink = |g: u32, s: u32| ev.push((g, s));
        badproto::BadProtocalCodec::new().decode(&cd, &mut sink)
    };
    assert_eq!(ev, vec![(116, 450)]); // vectors:9
    assert!(r); // vectors:10 -> 1
    assert_eq!(badproto::CD_BAD_PROTO[0].features, 1); // PLUGIN_SO_RELOAD vectors:5
}

// ---- ip/cd_no_next.rs ----

#[test]
/// vectors:14/:15 the short/ok arms: len 7 -> false SILENT; len 8
/// with default conf -> true + lyr=8 bits=0x10000 cnt=1; cc:66-:68
/// mutation set (lyr_len, proto_bits |= PROTO_BIT__IP6_EXT
/// (decode_data.h:103), ip6_extension_count++ wrapping) and NO other
/// CodecData field touched.
fn cd_no_next_ok_arm_mutations() {
    assert_eq!(fw::ip::MIN_EXT_LEN, 8); // ipv6.h:32
    assert_eq!(fw::PROTO_BIT__IP6_EXT, 0x010000); // decode_data.h:103 -- vectors:15 bits=10000
    let conf = SnortConfig::default();
    let mut ids = Vec::new();
    nonext::Ipv6NoNextCodec::new().get_protocol_ids(&mut ids);
    assert_eq!(ids, vec![59]); // protocol_ids.h NONEXT -- vectors:12
    let buf = [0u8; 8];
    let raw_short = fw::RawData { data: &buf, len: 7 };
    let raw_ok = fw::RawData { data: &buf, len: 8 };
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
    let mut sink = |_g: u32, _s: u32| panic!("no event expected vectors:14");
    assert!(!nonext::Ipv6NoNextCodec::new().decode(&raw_short, &mut cd, &mut sink));
    assert_eq!(cd.lyr_len, 0); // vectors:14 emitted no fields => untouched
    assert_eq!(cd.proto_bits, 0);
    assert_eq!(cd.ip6_extension_count, 0);
    let r = nonext::Ipv6NoNextCodec::new().decode(&raw_ok, &mut cd, &mut sink);
    assert!(r); // vectors:15 -> 1
    assert_eq!(cd.lyr_len, 8);
    assert_eq!(cd.proto_bits, 0x010000);
    assert_eq!(cd.ip6_extension_count, 1);
}

#[test]
/// the maxopts ladder (the hit_ip6_maxopts getter, snort_config.h:
/// :450-:451 wired onto the ported SnortConfig): C
/// `max_ip6_extensions && (curr_opt >= max_ip6_extensions)` --
/// zero-max never hits (vectors:15 face); max=2 hits at 2 (vectors:
/// 16/:17 EV 116 456 then false). sid 456 double-pinned: the enum
/// walk from the 450 comment AND the frozen vector.
fn cd_no_next_maxopts_ladder() {
    let c0 = SnortConfig::default();
    assert_eq!(c0.max_ip6_extensions, 0); // snort_config.h:278 NSDMI
    assert!(!c0.hit_ip6_maxopts(0)); // the && short-circuit face
    assert!(!c0.hit_ip6_maxopts(9));
    let mut c2 = SnortConfig::default();
    c2.max_ip6_extensions = 2;
    assert!(!c2.hit_ip6_maxopts(1)); // 1 >= 2 false
    assert!(c2.hit_ip6_maxopts(2)); // vectors:16 arm
    let buf = [0u8; 8];
    let raw = fw::RawData { data: &buf, len: 8 };
    let mut cd = fw::CodecData::new(Some(&c2), fw::protocol_id::ETHERTYPE_NOT_SET);
    cd.ip6_extension_count = 2;
    let mut ev: Vec<(u32, u32)> = Vec::new();
    let r = {
        let mut sink = |g: u32, s: u32| ev.push((g, s));
        nonext::Ipv6NoNextCodec::new().decode(&raw, &mut cd, &mut sink)
    };
    assert_eq!(ev, vec![(116, 456)]); // vectors:16 (fw::DECODE_IP6_EXCESS_EXT_HDR)
    assert_eq!(fw::DECODE_IP6_EXCESS_EXT_HDR, 456); // enum-walk pin double-check
    assert!(!r); // vectors:17 -> 0
    assert_eq!(cd.lyr_len, 0); // the hit arm mutates NOTHING (cc:55 before cc:66)
    assert_eq!(cd.proto_bits, 0);
    assert_eq!(cd.ip6_extension_count, 2);
}

// ---- root/cd_raw.rs ----

#[test]
/// vectors:19/:20/:21/:22/:23: DLT_RAW=12 (daq_dlt.h graft, libpcap
/// cite in the module docs) answers get_data_link_type; the ADD_DLT
/// splice (codec.h:52) is the HELP literal; the decode nibble ladder
/// 0x40 -> 2048 / 0x60 -> 34525 / else false WITHOUT touching
/// next_prot_id (bad arm printed no next= field -- CodecData stays
/// at its ETHERTYPE_NOT_SET init).
fn cd_raw_dlt_and_nibble_ladder() {
    assert_eq!(rawcodec::DLT_RAW, 12); // vectors:19
    let mut dlts = Vec::new();
    rawcodec::RawCodec::new().get_data_link_type(&mut dlts);
    assert_eq!(dlts, vec![12]);
    // ADD_DLT recipe re-composed and asserted equal to the splice literal
    assert_eq!(
        rawcodec::add_dlt(rawcodec::CD_RAW_HELP_STR, rawcodec::DLT_RAW),
        rawcodec::CD_RAW_HELP
    ); // vectors:20 == codec.h:52 splice at graft 12
    let conf = SnortConfig::default();
    let b4 = [0x45u8; 1];
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
    let raw = fw::RawData { data: &b4, len: 1 };
    assert!(rawcodec::RawCodec::new().decode(&raw, &mut cd));
    assert_eq!(cd.next_prot_id, 0x800); // vectors:21 next=2048
    let b6 = [0x60u8; 1];
    let mut cd6 = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
    let raw6 = fw::RawData { data: &b6, len: 1 };
    assert!(rawcodec::RawCodec::new().decode(&raw6, &mut cd6));
    assert_eq!(cd6.next_prot_id, 0x86DD); // vectors:22 next=34525
    let bx = [0x50u8; 1];
    let mut cdx = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_NOT_SET);
    let rawx = fw::RawData { data: &bx, len: 1 };
    assert!(!rawcodec::RawCodec::new().decode(&rawx, &mut cdx)); // vectors:23 -> 0
    assert_eq!(cdx.next_prot_id, 0); // cc:55 returns BEFORE any write
}

#[test]
/// the four record pins share the CDAPI face vectors repeat on line
/// 5/11/18: type=0 size=112 ver=1900547 features=1 except cd_default's
/// features=0 outlier (line 1) -- the one vocabulary fact the four
/// decoders differ on. ctor/dtor slots set in all; aux slots nullptr
/// in all (presence-bool posture, 17w/17z precedent).
fn vocab_record_face_census() {
    let recs = [
        &cdef::DEFAULT_API,
        &badproto::BAD_PROTO_API,
        &nonext::NO_NEXT_API,
        &rawcodec::RAW_API,
    ];
    for (r, want_feats) in recs.iter().zip([0u64, 1, 1, 1]) {
        assert_eq!(r.ptype, fw::PT_CODEC);
        assert_eq!(r.size, fw::CDAPI_SIZEOF_CODEC_API);
        assert_eq!(r.api_version, fw::CDAPI_VERSION);
        assert_eq!(r.version, 0);
        assert_eq!(r.features, want_feats);
        assert_eq!(r.options, fw::API_OPTIONS);
        assert!(r.ctor && r.dtor); // cc ctor/dtor set in all six records
        assert!(!r.pinit && !r.pterm && !r.tinit && !r.tterm); // 4x nullptr
        assert!(!r.mod_ctor && !r.mod_dtor); // 4x nullptr
    }
}
