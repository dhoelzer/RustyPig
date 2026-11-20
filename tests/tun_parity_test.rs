//! Parity test for the row-18f tunnel-trio port — 3 ground TUs
//! (misc/cd_teredo.cc 161 + misc/cd_gtp.cc 291 + misc/cd_geneve.cc
//! 282 = 734 L, every wc/md5 re-measured in tun PLAN §0 and asserted
//! every build by tools/tun_harness/build.sh).
//!
//! Ground truth #1: `tools/tun_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 40 L NEVER edited, md5
//! 2a7924796f8f0cfdca5e665dee28f519 (the -O0 == -O2 byte-ident pair
//! re-verified by the harness build.sh cmp arms, tun PLAN §3/§6).
//! WHOLE transcript replays HERE line-for-line as ONE ordered session
//! (the csum/vocab/eth/ext replay shape: per-index assert_eq over
//! want.len()==40 — ordered, never set-membership). probe_dec.cc
//! statement order == transcript order, the R6 var-before-printf
//! posture mirrored (build.sh greps the C face — `bool
//! *=.*->decode` count at least 10, `printf.*->decode` count zero)
//! — the Rust replay likewise stores
//! every decode bool BEFORE the post-decode field reads.
//!
//! Ground truth #2: `tools/tun_harness/vectors_faceA.txt` — the
//! FACE-A load face (probe.cc three-REAL-table walk through the
//! in-probe load_plugins witness), 7 L, md5
//! 81602890210d8d83068397c2cece1241 — replayed as the SECOND ordered
//! session (tun PLAN §6: BOTH faces tracked; mod_ctor asymmetry arms
//! geneve=1 gtp=1 teredo=0 re-pinned).
//!
//! Ground truth #3: the three misc/test suites (teredo_codec_test.cc
//! 121 L / gtp_codec_test.cc 140 L / geneve_codec_test.cc 163 L,
//! wc pinned by build.sh) — CppUTest dialect: TEST_GROUP x3, `^TEST(`
//! 2/2/3, CHECK-family 3/8/19, all self-including `../cd_*.cc` at
//! :29/:29/:20 (build.sh sed-pins the includes). The CppUTest runner
//! header is absent on this host — the E4_cpputest_fatal.txt wall
//! receipt is flipped-asserted EVERY build (18b/18e CppUTest
//! precedent: translated-not-run, never a fake gate). The 7 TESTs
//! translate BELOW as 7 `up_tun_*` fns, statement-for-statement,
//! each citing its C lines, PLUS the suite-local get_geneve_opt_data
//! helper (geneve_codec_test.cc:76-:99) as the 8th cited translation
//! — fixture literals copied byte-for-byte, NEVER re-derived. Bare
//! CHECK arms pin "the call returned" + the field checks the C
//! statement gives; every value derives from the C source (the
//! 18b unverifiable-fixture rule — no invented fixtures).
//!
//! Eval-order note (tun PLAN §6): EV lines land between the decode
//! call and the summary printf exactly as the C sink prints them
//! (queue_event EV-printer rides eth stubs_18d.cc there / the sink
//! closure here). The bypass hook replay mirrors
//! tools/tun_harness/witness_18f.cc byte-exactly: observable table
//! tun_mask + ground-shaped return `!((mask & proto) or daq)`, daq
//! arm pinned false (SFDAQ unlinked — tun PLAN §4).
//!
//! Asymmetries pinned by face HERE (deviations row 18f): teredo
//! ZERO codec_event arms (no sink in its decode signature at all) +
//! mod_ctor=0/mod_dtor=0 (vectors:40 + FACE-A:7); gtp encode
//! allocate-gate INVERSION + update_GTP_length never-true
//! (transcribed in the port, deviation-cited — never vectorized);
//! the DEC `GEN ... next=0` face (probe bytes 4-5 hit the VNI field,
//! NOT g_proto @2-3 — the emitted expression wins over the probe
//! comment, skill rule).

use snort3::codecs::cd_geneve as gnc;
use snort3::codecs::cd_gtp as gtpc;
use snort3::codecs::cd_teredo as tpc;
use snort3::framework::codec as fw;

const VECTORS: &str = include_str!("../tools/tun_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/tun_harness/vectors_faceA.txt");

/// probe_dec.cc:22 `uint8_t z[64]={0};` (and the a/o/o3/s/q6/v/w/x2b/
/// e4/q1/h2/c/h/o2 buffers — separate zeroed 64-B arrays, mutation
/// order per arm below). Verbatim posture.
fn buf64() -> [u8; 64] {
    [0u8; 64]
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 40 lines, ordered,
//    one session (probe_dec.cc statement order).
// ==========================================================================
#[test]
fn tun_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 40, "vectors.txt must hold the full 40-line DEC ladder");

    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };
    // the queue_event witness seam: `EV %u %u` (GID_DECODE 116 via the
    // landed framework codec_event — eth/ext lineage; ext PLAN §3).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };
    // the BYPASS seam: witness_18f.cc's ground-shaped body over the
    // observable table tun_mask (toggled per arm exactly where
    // probe_dec.cc calls tun_witness_set_mask): `!((tun_mask & proto)
    // or daq)`, daq_pypass pinned false (SFDAQ unlinked).
    let mut tun_mask: u16 = 0;

    // probe_dec.cc:18 api() x3 in call order geneve, gtp, teredo —
    // each an API line (type/size/ver/name) then a HELP line tagged
    // the same label. vectors:1-:6.
    {
        let api = |push: &dyn Fn(String), tag: &str, r: &fw::CodecApiRecord| {
            push(format!(
                "API {} type={} size={} ver={} name={}",
                tag, r.ptype, r.size, r.api_version, r.name
            ));
            push(format!("HELP {} {}", tag, r.help));
        };
        api(&push, "geneve", gnc::CD_GENEVE[0]); // vectors:1-2
        api(&push, "gtp", gtpc::CD_GTP[0]); // vectors:3-4
        api(&push, "teredo", tpc::CD_TEREDO[0]); // vectors:5-6
    }

    // -- TEREDO arms (probe_dec.cc:21-:40; ZERO-event TU — no sink) --
    let tt = tpc::TeredoCodec::new(); // ta->ctor(nullptr), probe_dec:21
    {
        // probe_dec.cc:22-:24: RawData t0(z, 1) — len 1 < MIN_HDR_LEN
        // 2 -> false, NO event. vectors:7 `TER short1 -> 0`.
        let z = buf64();
        let raw = fw::RawData { data: &z, len: 1 };
        let mut cd = fw::CodecData::new(None, tpc::PROTOCOL_ID_TEREDO);
        let ports = tpc::TeredoPorts::default();
        let x0 = tt.decode(&raw, &mut cd, &ports, &mut |_sid| !((tun_mask & _sid) != 0)); // R6: var first
        push(format!("TER short1 -> {}", x0 as i32));
    }
    {
        // probe_dec.cc:25-:27: a[1]=1 (indicator == INDICATOR_AUTH
        // 0x0001) at len 3 < INDICATOR_AUTH_MIN_LEN 13 -> false.
        // vectors:8 `TER auth-shord -> 0`.
        let mut a = buf64();
        a[1] = 1;
        let raw = fw::RawData { data: &a, len: 3 };
        let mut cd = fw::CodecData::new(None, tpc::PROTOCOL_ID_TEREDO);
        let ports = tpc::TeredoPorts::default();
        let x1 = tt.decode(&raw, &mut cd, &ports, &mut |_sid| !((tun_mask & _sid) != 0));
        push(format!("TER auth-shord -> {}", x1 as i32));
    }
    {
        // probe_dec.cc:28-:31: o[8]=0x60 (ORIGIN indicator 0x0000 at
        // bytes 0-1, 8 B consumed; IPv6 nibble 0x60 at byte 8);
        // tun_witness_set_mask(0) — the ground NSDMI tunnel_mask=0
        // face -> bypass TRUE -> tunnel_bypass set. vectors:9 `TER
        // mask0000 -> 1 bypass=1`.
        tun_mask = 0; // probe_dec.cc:29
        let mut o = buf64();
        o[8] = 0x60;
        let raw = fw::RawData { data: &o, len: 10 };
        let mut cd = fw::CodecData::new(None, tpc::PROTOCOL_ID_TEREDO);
        let ports = tpc::TeredoPorts::default();
        let x2 = tt.decode(&raw, &mut cd, &ports, &mut |sid| !((tun_mask & sid) != 0));
        push(format!(
            "TER mask0000 -> {} bypass={}",
            x2 as i32,
            cd.tunnel_bypass as i32
        ));
    }
    {
        // probe_dec.cc:32-:34: same buffer, mask 2 -> the
        // TUNNEL_TEREDO bit -> bypass FALSE. The success block writes
        // lyr 8 (ORIGIN arm), next IPV6 41, bits 128 (PROTO_BIT__
        // TEREDO 0x80), flags 646 (0x286 = TEREDO_SEEN|ENCAP|
        // NON_IP_TUNNEL — ports 0/0 != 3544 -> ENCAP arm fires).
        // (The C td3.sp=3544 write at probe_dec.cc:38 lands AFTER
        // td3.decode already ran AND on the wrong fixture for the
        // next arm — probe noise, never observable: untouched here.)
        // vectors:10.
        tun_mask = 2; // probe_dec.cc:32
        let mut o = buf64();
        o[8] = 0x60;
        let raw = fw::RawData { data: &o, len: 10 };
        let mut cd = fw::CodecData::new(None, tpc::PROTOCOL_ID_TEREDO);
        let ports = tpc::TeredoPorts::default();
        let x3 = tt.decode(&raw, &mut cd, &ports, &mut |sid| !((tun_mask & sid) != 0));
        push(format!(
            "TER mask0002 -> {} bypass={} lyr={} next={} bits={} flags={}",
            x3 as i32,
            cd.tunnel_bypass as i32,
            cd.lyr_len,
            cd.next_prot_id,
            cd.proto_bits,
            cd.codec_flags
        ));
    }
    {
        // probe_dec.cc:35-:39: o3[8]=0x60, mask STILL 2 (line 35
        // re-arms it), td4 fresh ports 0/0 -> the ENCAP arm.
        // vectors:11 `TER ports-off -> 1 flags=646`.
        tun_mask = 2;
        let mut o3 = buf64();
        o3[8] = 0x60;
        let raw = fw::RawData { data: &o3, len: 10 };
        let mut cd = fw::CodecData::new(None, tpc::PROTOCOL_ID_TEREDO);
        let ports = tpc::TeredoPorts::default();
        let x4 = tt.decode(&raw, &mut cd, &ports, &mut |sid| !((tun_mask & sid) != 0));
        push(format!("TER ports-off -> {} flags={}", x4 as i32, cd.codec_flags));
    }
    {
        // probe_dec.cc:40 PIDS. vectors:12 `TERPID 257 n=1`.
        let mut tv = Vec::new();
        tt.get_protocol_ids(&mut tv);
        push(format!("TERPID {} n={}", tv[0], tv.len()));
    }

    // -- GTP arms (probe_dec.cc:44-:70; sink for the 298/297 family) --
    let gg = gtpc::GtpCodec::new(); // ga->ctor(nullptr), probe_dec:44
    {
        // probe_dec.cc:45-:46: RawData g0(z, 7) — len < GTP_MIN_LEN
        // 8 -> false NO event. vectors:13.
        let z = buf64();
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let g0b = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GTP short7 -> {}", g0b as i32));
    }
    {
        // probe_dec.cc:47-:49: s[0]=0x10 (v0, PT bit) s[1]=1 (type
        // != 255) -> false. vectors:14 `GTP type1 -> 0`.
        let mut s = buf64();
        s[0] = 0x10;
        s[1] = 0x01;
        let raw = fw::RawData { data: &s, len: 8 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let g1b = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GTP type1 -> {}", g1b as i32));
    }
    {
        // probe_dec.cc:50-:52: q6[0]=0x20 (v2... version 1 shifted?
        // no: flag 0x20 = version 1 face with the PT bit 0x10 CLEAR)
        // -> the GTP'-exit arm -> false. vectors:15 `GTP gtpprime`.
        let mut q6 = buf64();
        q6[0] = 0x20;
        q6[1] = 0xff;
        let raw = fw::RawData { data: &q6, len: 8 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let gqb = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GTP gtpprime -> {}", gqb as i32));
    }
    {
        // probe_dec.cc:53-:55: v[0]=0x10 v[1]=0xff len 8: v0 arm,
        // raw 8 < GTP_V0_HEADER_LEN 20 -> EV 116 298 THEN false.
        // vectors:16-:17.
        let mut v = buf64();
        v[0] = 0x10;
        v[1] = 0xff;
        let raw = fw::RawData { data: &v, len: 8 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let g2b = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GTP v0-shord -> {}", g2b as i32));
    }
    {
        // probe_dec.cc:56-:59: w[0]=0x30 (v1, no optional bits)
        // w[1]=0xff, length field 0: 8 == 0+8 ok; tun mask 1 ->
        // TUNNEL_GTP bit -> bypass FALSE; lyr 8, bits 256. The gd3
        // decode_flags latch bit is SET by this arm (cc:186).
        // vectors:18.
        tun_mask = 1; // probe_dec.cc:57
        let mut w = buf64();
        w[0] = 0x30;
        w[1] = 0xff;
        let raw = fw::RawData { data: &w, len: 8 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let g3b = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!(
            "GTP v1-ok mask0001 -> {} bypass={} lyr={} bits={}",
            g3b as i32,
            cd.tunnel_bypass as i32,
            cd.lyr_len,
            cd.proto_bits
        ));
        // the gd3 face carries the latch for the next arm (Copy).
        let mut gd3 = dd;
        {
            // probe_dec.cc:60-:61: gdd = gd3 COPY + explicit
            // `gdd.decode_flags |= 0x1000` (DECODE_GTP) -> the
            // multi-encap EV 116 297 fires, decode STILL TRUE.
            // vectors:19-:20. (bit already set via the copy; the C
            // explicit OR is kept verbatim anyway)
            gd3.decode_flags |= gtpc::DECODE_GTP;
            let raw = fw::RawData { data: &w, len: 8 };
            let mut cd4 = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
            let mut gdd = gd3;
            let g4b = gg.decode(&raw, &mut cd4, &mut gdd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
            push(format!("GTP v1-twice -> {}", g4b as i32));
        }
    }
    {
        // probe_dec.cc:62-:65: mask 0; x2b[0]=0x30 x2b[1]=0xff
        // x2b[2]=0x00 x2b[3]=0x05: v1, length field 5 -> 8 != 5+8 ->
        // EV 116 298 (the SECOND measured 298 — build.sh counts the
        // family EXACTLY 2) + false. vectors:21-:22.
        tun_mask = 0;
        let mut x2b = buf64();
        x2b[0] = 0x30;
        x2b[1] = 0xff;
        x2b[2] = 0x00;
        x2b[3] = 0x05;
        let raw = fw::RawData { data: &x2b, len: 8 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let g5b = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GTP v1-badlen -> {}", g5b as i32));
    }
    {
        // probe_dec.cc:66-:69: e4[0]=0x30 e4[1]=0xff e4[3]=0x08
        // (length field 8: raw 16 == 8+8 ok), e4[8]=0x45 -> inner
        // nibble 0x40 at raw.data+len(8) -> next IPIP 4, ENCAP fires,
        // flags 518 (0x206). mask still 0 -> bypass TRUE (not printed
        // on this line — the C printf face kept expression-exact).
        // vectors:23.
        let mut e4 = buf64();
        e4[0] = 0x30;
        e4[1] = 0xff;
        e4[3] = 0x08;
        e4[8] = 0x45;
        let raw = fw::RawData { data: &e4, len: 16 };
        let mut cd = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP);
        let mut dd = gtpc::GtpDecodeFlags::default();
        let g6b = gg.decode(&raw, &mut cd, &mut dd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!(
            "GTP v1-encap -> {} next={} lyr={} flags={}",
            g6b as i32,
            cd.next_prot_id,
            cd.lyr_len,
            cd.codec_flags
        ));
    }
    {
        // probe_dec.cc:70 PIDS. vectors:24 `GTPPID 258 n=1`.
        let mut gv = Vec::new();
        gg.get_protocol_ids(&mut gv);
        push(format!("GTPPID {} n={}", gv[0], gv.len()));
    }

    // -- GENEVE arms (probe_dec.cc:74-:97; EV family 180-184 all
    // vectors-pinned as EV-then-summary pairs) --
    let nq = gnc::GeneveCodec::new(); // na->ctor(nullptr), probe_dec:74
    {
        // probe_dec.cc:75-:76: n0(z, 7): len < 8 -> EV 116 180 +
        // false. vectors:25-:26.
        let z = buf64();
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n0b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GEN short7 -> {}", n0b as i32));
    }
    {
        // probe_dec.cc:77-:79: q1[0]=0x40 -> version bits 1 !=
        // RFC_8926_GENEVE_VERSION 0 -> EV 116 181 + false.
        // vectors:27-:28.
        let mut q1 = buf64();
        q1[0] = 0x40;
        let raw = fw::RawData { data: &q1, len: 8 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n1b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GEN ver1 -> {}", n1b as i32));
    }
    {
        // probe_dec.cc:80-:82: h2[0]=0x3f -> opts_len 0x3f*4=252,
        // hdrlen 260 > len 8 -> EV 116 182 + false. vectors:29-:30.
        let mut h2 = buf64();
        h2[0] = 0x3f;
        let raw = fw::RawData { data: &h2, len: 8 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n2b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GEN hdr-long -> {}", n2b as i32));
    }
    {
        // probe_dec.cc:83-:86: c[0]=0x01 (opts_len 4, hdrlen 12),
        // c[1]=0x40 (C flag set), c[4..8]=00 00 65 58 -> the option
        // at bytes 8-11 is ZERO (olen 4): 8+4 = 12 NOT > 12 -> walk
        // clean, copts 0 (g_type byte 10 = 0) BUT C flag set +
        // copts 0 -> EV 116 183 (the cc:121 XOR face) + false.
        // Probe comment says "INVALID_FLAGS face skipped" — the
        // EXPRESSION wins: the emitted EV 183 is the pin (vectors:
        // :31-:32), probe comment recorded as noise in deviations.
        let mut c = buf64();
        c[0] = 0x01;
        c[1] = 0x40;
        c[4] = 0x00;
        c[5] = 0x00;
        c[6] = 0x65;
        c[7] = 0x58;
        let raw = fw::RawData { data: &c, len: 12 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n3b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GEN C-no-copt -> {}", n3b as i32));
    }
    {
        // probe_dec.cc:87-:90: h[4]=0x65 h[5]=0x58 — bytes 4-5 are
        // the VNI, NOT g_proto (@2-3): proto() reads 0 -> next=0,
        // NOT the ETHERNET face the probe comment claims (the
        // STRUCT-OFFSET FACT, module header). opts_len 0 -> hdrlen
        // 8, walk empty; mask 0x200 -> TUNNEL_GENEVE bit -> bypass
        // FALSE. bits = PROTO_BIT__GENEVE 0x200000 = 2097152.
        // vectors:33.
        tun_mask = 0x200;
        let mut h = buf64();
        h[4] = 0x65;
        h[5] = 0x58;
        let raw = fw::RawData { data: &h, len: 8 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n4b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!(
            "GEN mask0200 -> {} bypass={} lyr={} next={} bits={}",
            n4b as i32,
            cd.tunnel_bypass as i32,
            cd.lyr_len,
            cd.next_prot_id,
            cd.proto_bits
        ));
    }
    {
        // probe_dec.cc:91-:93: same buffer, mask 0 (ground default)
        // -> bypass TRUE. vectors:34.
        tun_mask = 0;
        let mut h = buf64();
        h[4] = 0x65;
        h[5] = 0x58;
        let raw = fw::RawData { data: &h, len: 8 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n5b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!(
            "GEN mask0000 -> {} bypass={}",
            n5b as i32,
            cd.tunnel_bypass as i32
        ));
    }
    {
        // probe_dec.cc:94-:96: o2[0]=0x01 (opts_len 4, hdrlen 12),
        // o2[11]=0x07 -> the option g_len at cc:validate reads
        // olen = 4 + (0x07 & 0x1f)*4 = 32: 8+32 > 12 -> EV 116 184
        // (raised INSIDE validate_options, before the summary).
        // vectors:35-:36.
        let mut o2 = buf64();
        o2[0] = 0x01;
        o2[4] = 0x65;
        o2[5] = 0x58;
        o2[11] = 0x07;
        let raw = fw::RawData { data: &o2, len: 12 };
        let mut cd = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE);
        let n6b = nq.decode(&raw, &mut cd, &mut |sid| !((tun_mask & sid) != 0), &mut sink);
        push(format!("GEN badopt -> {}", n6b as i32));
    }
    {
        // probe_dec.cc:97 PIDS. vectors:37 `GENPID 265 n=1`.
        let mut nv = Vec::new();
        nq.get_protocol_ids(&mut nv);
        push(format!("GENPID {} n={}", nv[0], nv.len()));
    }

    // -- module/RuleMap faces (probe_dec.cc:99-:103; tun PLAN §6:
    // geneve 5 rows sid0 180, gtp 2 rows sid0 297 — the landed
    // codec_module.rs RuleMap/rule_count homes carry the tables;
    // teredo NO module: the record's nullptr mod pair, vectors:40) --
    {
        let nm = gnc::GeneveModule::new(); // nb->mod_ctor(), probe_dec:99
        let nr = gnc::GeneveModule::get_rules();
        let ncc = snort3::codecs::codec_module::rule_count(nr); // while(sid) walk
        push(format!(
            "GEN rules={} sid0={} name={}",
            ncc, nr[0].sid,
            nm.get_name()
        ));
        // nb->mod_dtor(nm) — stack-owned drop (18d posture).
    }
    {
        let gm = gtpc::GtpModule::new(); // gb->mod_ctor(), probe_dec:101
        let gr = gtpc::GtpModule::get_rules();
        let gc7 = snort3::codecs::codec_module::rule_count(gr);
        push(format!(
            "GTP rules={} sid0={} name={}",
            gc7, gr[0].sid,
            gm.get_name()
        ));
    }
    {
        // probe_dec.cc:103: `ta->base.mod_ctor?1:0, ta->base.
        // mod_dtor?1:0` — the teredo nullptr pair. vectors:40.
        let ta = tpc::CD_TEREDO[0];
        push(format!(
            "TER mod_ctor={} mod_dtor={}",
            ta.mod_ctor as i32,
            ta.mod_dtor as i32
        ));
    }

    for (i, (got, want_line)) in out.borrow().iter().zip(want.iter()).enumerate() {
        assert_eq!(got, want_line, "DEC transcript line {}", i + 1);
    }
    assert_eq!(out.borrow().len(), 40, "replay must emit exactly 40 lines");
}

// ==========================================================================
// 2. FACE-A load-face replay — vectors_faceA.txt 7 lines, ordered
//    (probe.cc tab walk {cd_geneve, cd_gtp, cd_teredo} through the
//    in-probe load_plugins witness; tun PLAN §6: mod_ctor asymmetry
//    geneve=1 gtp=1 teredo=0 — the honest arm).
// ==========================================================================
#[test]
fn tun_face_a_load_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 7, "vectors_faceA.txt must hold the full 7-line load ladder");

    let mut out: Vec<String> = Vec::new();
    // probe.cc:14 `tabs[] = { cd_geneve, cd_gtp, cd_teredo }` walked
    // through the load_plugins witness (`for (; p && *p; ++p) printf(
    // "LOAD %s", (*p)->name)`): the REAL names (the probe link pulls
    // NO codec_api object — tun PLAN §5 nm guard).
    let tabs: [fw::CodecTable; 3] = [gnc::CD_GENEVE, gtpc::CD_GTP, tpc::CD_TEREDO];
    for t in tabs {
        for rec in t {
            out.push(format!("LOAD {}", rec.name));
        }
    }
    out.push("LOADS 3".to_string()); // probe.cc:16
    // probe.cc:17 geneve record face (BaseApi slots). vectors:5.
    let g = gnc::CD_GENEVE[0];
    out.push(format!(
        "API geneve type={} size={} ver={} name={}",
        g.ptype, g.size, g.api_version, g.name
    ));
    // probe.cc:18-:19 the mod_ctor asymmetry pair. vectors:6-7.
    let t = gtpc::CD_GTP[0];
    out.push(format!("API gtp mod_ctor={}", t.mod_ctor as i32));
    let r = tpc::CD_TEREDO[0];
    out.push(format!("API teredo mod_ctor={}", r.mod_ctor as i32));

    for (line, (got, want_line)) in out.iter().zip(want.iter()).enumerate() {
        assert_eq!(got, want_line, "FACE-A transcript line {}", line + 1);
    }
    assert_eq!(out.len(), 7, "FACE-A replay must emit exactly 7 lines");
}

// ==========================================================================
// 3. Upstream-suite translations — the misc/test trio, 7 TEST( units
//    + the suite-local get_geneve_opt_data helper = 8 up_tun_* fns.
//    CppUTest wall (tun PLAN §3): E4_cpputest_fatal.txt receipts
//    `CppUTest/CommandLineTestRunner.h: No such file` x3, flipped-
//    assert EVERY build — translated Rust, never a fake gate (18b
//    precedent). The C suite stub block (teredo :41-:49 / gtp :162-
//    :171 / geneve :35-:43 — the three files repeat it verbatim):
//    tunnel_bypass_enabled -> false, TextLog_Print -> false,
//    Codec::codec_event -> {} (silent), get_instance_id -> 0. So the
//    bypass hook below returns false on EVERY sid (the suite face),
//    the sink stays SILENT (no event armed on any suite arm) and the
//    event count is asserted zero per test.
//    ExactPayload (teredo :52-:72 / gtp :176-:197, identical bodies):
//    heap malloc(N) + memcpy — the exactly-sized buffer (the gtp :174-
//    :175 ASAN comment pins why: a single-byte OOB must fault). The
//    Rust translation passes slices; the exact-size face is carried
//    by len == array size (the fixture sizes ARE the pin — no
//    64-byte slack like the probe buffers: decode must never read
//    past the payload, exactly the regression the C suite guards).
// ==========================================================================

/// the suite stub face: `bool SnortConfig::tunnel_bypass_enabled(
/// unsigned short) const { return false; }` (teredo:41, gtp:162,
/// geneve:35 — cited per translation below).
fn suite_bypass(_sid: u16) -> bool {
    false
}

/// teredo_codec_test.cc:74-:84 `decode_teredo_payload` — TeredoCodec
/// stack fixture, `CodecData codec_data(nullptr, ProtocolId::TEREDO)`,
/// fresh DecodeData, `decode_data.sp = teredo::TEREDO_PORT` (3544) +
/// `.dp = 6666` (:79-:80 — the fixture face; both arms below return
/// BEFORE the cc:109 ports read, so the values are carried verbatim
/// and never observable on these faces — the comment kept).
fn up_tun_teredo_fixture_decode(payload: &[u8]) -> bool {
    let codec = tpc::TeredoCodec::new();
    let mut codec_data = fw::CodecData::new(None, tpc::PROTOCOL_ID_TEREDO);
    let decode_data = tpc::TeredoPorts {
        sp: tpc::TEREDO_PORT, // :79
        dp: 6666,             // :80
    };
    let raw = fw::RawData {
        data: payload,
        len: payload.len() as u32, // ExactPayload::size() == N
    };
    codec.decode(&raw, &mut codec_data, &decode_data, &mut suite_bypass)
}

/// C suite TEST #1 — teredo_codec_test.cc:90-:101 `rejects_payload_
/// ending_after_auth_indicator`: auth_only_min[13] = {0x00,0x01,
/// 0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,0x33} (bytes
/// :94-:95 verbatim) -> CHECK_FALSE. C trace: indicator 0x0001 ==
/// AUTH (:68 -> true, cited); len 13 NOT < 13 (:70 passes); client/
/// auth length bytes @2-3 = 0+0 -> need 13, 13 not < 13 (:76);
/// consumed 13, raw_pkt 13; cc:84 `raw.len < 13+2` -> RETURN FALSE.
/// The 5 trailing 0xAA.. bytes exist ONLY to fill — pin: false.
#[test]
fn up_tun_teredo_rejects_payload_ending_after_auth_indicator() {
    static AUTH_ONLY_MIN: [u8; 13] = [
        0x00, 0x01, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33,
    ];
    // CHECK_FALSE(decode_teredo_payload(payload)); — :100
    assert!(!up_tun_teredo_fixture_decode(&AUTH_ONLY_MIN));
}

/// C suite TEST #2 — teredo_codec_test.cc:103-:113 `rejects_payload_
/// ending_after_origin_indicator`: origin_only_len[8] = 8 zero bytes
/// (:107) -> CHECK_FALSE. C trace: indicator 0 != AUTH (:68 skip);
/// 8 >= 0+2 (:84); indicator 0 == ORIGIN (:87 -> true); 8 >= 0+8
/// (:89 passes) -> consumed 8, lyr 8; cc:97 `8 < 8+1` -> RETURN
/// FALSE at cc:98 (the IPv6 nibble read at cc:101 is NEVER reached —
/// the payload-ends-after-origin guard, zero events: the teredo zero-
/// event asymmetry, port signature carries no sink).
#[test]
fn up_tun_teredo_rejects_payload_ending_after_origin_indicator() {
    // the C literal origin_only_len[8] (:107): indicator 0x0000 +
    // four filler pairs — byte-for-byte:
    static ORIGIN_ONLY_LEN: [u8; 8] = [0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    // CHECK_FALSE(...); — :112
    assert!(!up_tun_teredo_fixture_decode(&ORIGIN_ONLY_LEN));
}

/// gtp fixture driver — gtp_codec_test.cc:199-:206
/// `decode_gtp_payload(payload, codec_data)`: the CodecData comes IN
/// from the test (caller-owned, `CodecData(nullptr, ProtocolId::
/// GTP)` at :226/:248 — the fresh-decode face keeps lyr/bits/flags
/// reads post-call), fresh DecodeData; bypass stub false (:162).
/// The suite arms raise NO codec_event (verified post-call below).
fn up_tun_gtp_fixture_decode(payload: &[u8], codec_data: &mut fw::CodecData<'_>) -> bool {
    let codec = gtpc::GtpCodec::new();
    let mut decode_data = gtpc::GtpDecodeFlags::default();
    let raw = fw::RawData {
        data: payload,
        len: payload.len() as u32,
    };
    let mut sink_events = 0usize; // the suite stub `Codec::codec_event{}` — silent
    let mut sink = |_gid: u32, _sid: u32| sink_events += 1;
    let r = codec.decode(&raw, codec_data, &mut decode_data, &mut suite_bypass, &mut sink);
    // the silent-stub face doubles as the observed pin:
    assert_eq!(sink_events, 0, "gtp suite fixture arms raise NO event");
    r
}

/// C suite TEST #3 — gtp_codec_test.cc:214-:233 `gtpv1_header_fills_
/// packet_no_inner_read` (the :212-:213 regression comment: "the
/// OOB read of the inner-IP version byte when a well-formed GTP
/// header exactly fills the packet"): gtpv1_no_payload[8] = {0x30,
/// 0xFF, 0,0,0,0,0,0} (:221 verbatim). C trace: 8 >= 8 (:93); type
/// 255 (:96 -> pass); flag 0x30 & 0x10 set (:99 -> not GTP');
/// version 1; flag & 0x07 == 0 -> len = GTP_MIN_LEN 8 (:164);
/// length field 0: 8 == 0+8 (:166 passes); bypass false (:177 no
/// set); lyr 8 (:180), bits GTP (:181); DECODE_GTP bit CLEAR -> OR
/// it in (:186); `raw.len > len` -> 8 > 8 FALSE: the cc:191 read
/// NEVER FIRES (the exact-fills guard the suite exists for); flags
/// = NON_IP_TUNNEL only. CHECK(decode) :227, CHECK ENCAP==0 :231,
/// CHECK NON_IP_TUNNEL :232.
#[test]
fn up_tun_gtp_gtpv1_header_fills_packet_no_inner_read() {
    static GTPV1_NO_PAYLOAD: [u8; 8] = [0x30, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut codec_data = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP); // :226
    // CHECK(decode_gtp_payload(payload, codec_data)); — :227
    assert!(up_tun_gtp_fixture_decode(&GTPV1_NO_PAYLOAD, &mut codec_data));
    // CHECK((codec_data.codec_flags & CODEC_ENCAP_LAYER) == 0); — :231
    assert_eq!(codec_data.codec_flags & fw::CODEC_ENCAP_LAYER, 0);
    // CHECK(codec_data.codec_flags & CODEC_NON_IP_TUNNEL); — :232
    assert_ne!(codec_data.codec_flags & fw::CODEC_NON_IP_TUNNEL, 0);
}

/// C suite TEST #4 — gtp_codec_test.cc:237-:253 `gtpv0_header_fills_
/// packet_no_inner_read`: gtpv0_no_payload[20] = {0x10,0xFF,0x00...}
/// (:241-:243 verbatim). C trace: v0 arm len = GTP_V0_HEADER_LEN 20
/// (:107); 20 >= 20 (:108 passes); length field 0: raw 20 == 0+20
/// (:114 passes); lyr 20; `20 > 20` FALSE -> no cc:191 read again;
/// flags NON_IP_TUNNEL only. CHECK(decode) :249, ENCAP 0 :251,
/// NON_IP_TUNNEL :252.
#[test]
fn up_tun_gtp_gtpv0_header_fills_packet_no_inner_read() {
    static GTPV0_NO_PAYLOAD: [u8; 20] = [
        0x10, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut codec_data = fw::CodecData::new(None, gtpc::PROTOCOL_ID_GTP); // :248
    // CHECK(decode_gtp_payload(payload, codec_data)); — :249
    assert!(up_tun_gtp_fixture_decode(&GTPV0_NO_PAYLOAD, &mut codec_data));
    // CHECK((codec_data.codec_flags & CODEC_ENCAP_LAYER) == 0); — :251
    assert_eq!(codec_data.codec_flags & fw::CODEC_ENCAP_LAYER, 0);
    // CHECK(codec_data.codec_flags & CODEC_NON_IP_TUNNEL); — :252
    assert_ne!(codec_data.codec_flags & fw::CODEC_NON_IP_TUNNEL, 0);
}

/// geneve fixture literals — geneve_codec_test.cc:44-:57
/// geneve_pkt_data (28 B: 8-B hdr g_vl 0x05 (ver 0, opts 5x4=20) +
/// 12-B option class 0x0106 type 0x56 len 2x4 + 8-B option class
/// 0x0106 type 0x02 len 1x4) and :60-:66 geneve_pkt_data_no_options
/// (8 B, opts 0) — BOTH byte-for-byte, comments transcribed.
static GENEVE_PKT_DATA: [u8; 28] = [
    0x05, // version and option length in 4-byte chunks      (:45)
    0x00, // flags                                          (:46)
    0x65, 0x58, // protocol type                            (:47)
    0x00, 0x00, 0x01, // VNI                                (:48)
    0x00, // reserved                                      (:49)
    0x01, 0x06, // Cisco variable option class              (:50)
    0x56, // Variable option type                           (:51)
    0x02, // Variable option data length in 4-byte chunks   (:52)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, // option data (:53)
    0x01, 0x06, // Cisco variable option class              (:54)
    0x02, // Variable option type                           (:55)
    0x01, // Variable option data length in 4-byte chunks   (:56)
    0xac, 0x10, 0xa0, 0x02, // option data                  (:57)
];

static GENEVE_PKT_DATA_NO_OPTIONS: [u8; 8] = [
    0x00, // version and option length in 4-byte chunks     (:61)
    0x00, // flags                                          (:62)
    0x65, 0x58, // protocol type                            (:63)
    0x00, 0x00, 0x01, // VNI                                (:64)
    0x00, // reserved                                      (:65)
];

/// C suite TEST #5 — geneve_codec_test.cc:107-:119 `decode`:
/// CHECK_TRUE(decode) :113; CHECK(lyr_len == sizeof(geneve_pkt_
/// data) == 28) :114 — the port's hlen() = 8 + (0x05&0x3f)*4 = 28
/// (geneve.h:99-:100, the fixture's own hdrlen == the full packet);
/// CHECK(proto_bits == PROTO_BIT__GENEVE) :115; CHECK(next ==
/// ETHERNET_802_3) :116 — bytes 2-3 = 0x6558 == GENEVE_ETH_TYPE
/// (cd_geneve.cc:170; the DEC mask0200 next=0 face is the DIFFERENT
/// probe buffer, module header STRUCT-OFFSET FACT — here the suite
/// fixture hits g_proto PROPERLY); CHECK(codec_flags ==
/// CODEC_NON_IP_TUNNEL) :117 (fresh CodecData, single OR). bypass
/// stub false (:35) -> no tunnel_bypass; C flag clear -> cc:155 +
/// the validate XOR both silent; zero events.
#[test]
fn up_tun_geneve_decode() {
    let codec = gnc::GeneveCodec::new(); // :108
    let raw = fw::RawData {
        data: &GENEVE_PKT_DATA,
        len: GENEVE_PKT_DATA.len() as u32, // sizeof (:109)
    };
    let mut codec_data = fw::CodecData::new(None, gnc::PROTOCOL_ID_GENEVE); // :110
    // DecodeData :111 is NEVER READ by the C decode (cc:130 names it
    // with no operand) — no Rust stand-in needed, cite kept here.
    let mut n_events = 0usize;
    let mut sink = |_gid: u32, _sid: u32| n_events += 1;
    // CHECK_TRUE( geneve_codec.decode(raw_data, codec_data, decode_data) ); :113
    let r = codec.decode(&raw, &mut codec_data, &mut suite_bypass, &mut sink);
    assert!(r, "geneve suite fixture decode: CHECK_TRUE");
    assert_eq!(n_events, 0, "geneve decode fixture arm raises NO event (silent stub face)");
    // CHECK(codec_data.lyr_len == sizeof(geneve_pkt_data)); :114
    assert_eq!(codec_data.lyr_len as usize, GENEVE_PKT_DATA.len());
    // CHECK(codec_data.proto_bits == PROTO_BIT__GENEVE); :115 (fresh struct -> ==)
    assert_eq!(codec_data.proto_bits, gnc::PROTO_BIT__GENEVE);
    // CHECK(codec_data.next_prot_id == ProtocolId::ETHERNET_802_3); :116
    assert_eq!(
        codec_data.next_prot_id,
        fw::protocol_id::ETHERNET_802_3 // 261 — landed 18d
    );
    // CHECK(codec_data.codec_flags == CODEC_NON_IP_TUNNEL); :117
    assert_eq!(codec_data.codec_flags, fw::CODEC_NON_IP_TUNNEL);
}

/// the 8th translation — geneve_codec_test.cc:72-:98 the SUITE-LOCAL
/// helper `get_geneve_opt_data(options, class, type, value)`: value=0
/// then linear scan; class+type match: data_len 4 -> ntohl(u32*
/// data), 8 -> ntohll(u64*data), ELSE return false, return true;
/// miss -> false. (Arms both value widths + the miss; the :147-:148
/// TEST asserts consume it.)
fn up_tun_geneve_get_opt_data(
    options: &[gnc::GeneveOptData],
    g_class: u16,
    g_type: u8,
    value: &mut u64,
) -> bool {
    *value = 0; // :74
    for opt_data in options {
        if opt_data.opt.optclass() == g_class && opt_data.opt.type_() == g_type {
            let data_len = opt_data.opt.data_len(); // :80
            if data_len == 4 {
                *value = u32::from_be_bytes([
                    opt_data.data[0],
                    opt_data.data[1],
                    opt_data.data[2],
                    opt_data.data[3],
                ]) as u64; // :82 ntohl
            } else if data_len == 8 {
                *value = u64::from_be_bytes([
                    opt_data.data[0],
                    opt_data.data[1],
                    opt_data.data[2],
                    opt_data.data[3],
                    opt_data.data[4],
                    opt_data.data[5],
                    opt_data.data[6],
                    opt_data.data[7],
                ]); // :84 ntohll
            } else {
                return false; // :86
            }
            return true; // :88
        }
    }
    false // :91
}

/// C suite TEST #6 — geneve_codec_test.cc:121-:148 `geneve_lyr`:
/// GeneveLyr overlay over the 28-B fixture + get_opt_data()
/// (geneve.h:124-:146 — the ROW-SCOPED gnc::geneve_get_opt_data
/// landed with the port, cite in its doc). CHECKs verbatim: size 2
/// (:127); opt0 olen 12 (:129) data_len 8 (:130) class 0x0106 (:131)
/// type 0x56 (:132); data == {0,0,0,0,0,0,0x08,0x40} memcmp (:135-
/// :136); opt1 olen 8 (:138) data_len 4 (:139) class 0x0106 (:140)
/// type 0x02 (:141); data == {0xac,0x10,0xa0,0x02} memcmp (:144-
/// :145); get_geneve_opt_data(0x0106, 0x56) true (:148-CHECK :149) +
/// value == 2112 (:150 — 0x0000000000000840 via the 8-byte ntohll
/// arm).
#[test]
fn up_tun_geneve_geneve_lyr() {
    let opt_data = gnc::geneve_get_opt_data(&GENEVE_PKT_DATA);
    // CHECK( opt_data.size() == 2 ); :127
    assert_eq!(opt_data.len(), 2);
    // CHECK( opt_data[0].opt.olen() == 12 ); :129
    assert_eq!(opt_data[0].opt.olen(), 12);
    // CHECK( opt_data[0].opt.data_len() == 8 ); :130
    assert_eq!(opt_data[0].opt.data_len(), 8);
    // CHECK( opt_data[0].opt.optclass() == 0x0106 ); :131
    assert_eq!(opt_data[0].opt.optclass(), 0x0106);
    // CHECK( opt_data[0].opt.type() == 0x56 ); :132 (C member `type`,
    // the Rust raw-value fn keeps type_ — deviations fold note)
    assert_eq!(opt_data[0].opt.type_(), 0x56);
    // const uint8_t opt0_data[] = {0,...,0x08,0x40}; memcmp == 0 :135-:136
    assert_eq!(opt_data[0].data, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40]);
    // CHECK( opt_data[1].opt.olen() == 8 ); :138
    assert_eq!(opt_data[1].opt.olen(), 8);
    // CHECK( opt_data[1].opt.data_len() == 4 ); :139
    assert_eq!(opt_data[1].opt.data_len(), 4);
    // CHECK( opt_data[1].opt.optclass() == 0x0106 ); :140
    assert_eq!(opt_data[1].opt.optclass(), 0x0106);
    // CHECK( opt_data[1].opt.type() == 0x02 ); :141
    assert_eq!(opt_data[1].opt.type_(), 0x02);
    // const uint8_t opt1_data[] = {0xac,0x10,0xa0,0x02}; memcmp :144-:145
    assert_eq!(opt_data[1].data, vec![0xac, 0x10, 0xa0, 0x02]);
    // CHECK( get_geneve_opt_data(opt_data, 0x0106, 0x56, value) ); :147
    let mut value: u64 = 0;
    assert!(up_tun_geneve_get_opt_data(&opt_data, 0x0106, 0x56, &mut value));
    // CHECK( value == 2112 ); :148
    assert_eq!(value, 2112);
}

/// C suite TEST #7 — geneve_codec_test.cc:150-:156
/// `geneve_lyr_no_options`: the 8-B opts-0 fixture ->
/// CHECK( opt_data.empty() ); :155 (geneve.h:131 `while (offset <
/// all_opt_len)` never enters with all_opt_len 0).
#[test]
fn up_tun_geneve_geneve_lyr_no_options() {
    let opt_data = gnc::geneve_get_opt_data(&GENEVE_PKT_DATA_NO_OPTIONS);
    // CHECK( opt_data.empty() ); :155
    assert!(opt_data.is_empty());
}
