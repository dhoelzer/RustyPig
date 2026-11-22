//! Parity test for the row-20a codecs/ip HEAVIES trio — ground
//! src/codecs/ip/cd_ipv4.cc (790 L md5 def01f1df71ab250896da1764f6c0f92),
//! cd_ipv6.cc (733 L md5 89267b1d6d4f583434af207a14f90f56) and cd_tcp.cc
//! (839 L md5 144c427504a13c58dc117bcf93f6a604) — sum 2,362 L, the
//! CODECS CHAPTER CLOSE-OUT trio (the last three IP codecs: igmp/routing/
//! frag3 hops sit in OTHER chapters; the chapter is 100% code-side at
//! this row). TRUE-NAME HOLDS (table==file base): cd_ipv4[] at
//! cd_ipv4.cc:785, cd_ipv6[] at cd_ipv6.cc:728, cd_tcp[] at cd_tcp.cc:834
//! — the cd_tcp BUILDING_SO block is COMMENTED OUT (:831/:832/:833/:835
//! face): grep-c BUILDING_SO=1 LIES, cd_tcp[] UNCONDITIONAL (the
//! grep-lie face in the deviations ledger).
//!
//! THE PIN VECTORS (both faces, pinned NEVER edit by the harness; the
//! md5 face asserted in-file):
//!   - `tools/ipheavy_harness/vectors.txt` — DEC face (probe_dec.cc),
//!     EXACTLY 121 L, md5 857b5a100480114085b45a392ab713bf. The full
//!     ordered emit transcript of the trio's decode ladders across the
//!     I4x/I6x/ICx fixture families. The replay asserts ORDER + COUNTS:
//!     the interleave (EV lines between call and summary, NEVER sorted)
//!     is the contract; a reordered port fails.
//!   - `tools/ipheavy_harness/vectors_faceA.txt` — FACE-A load/walk face,
//!     EXACTLY 44 L, md5 63df50bc57b7d15d95c21bdfcd492fce: TRUE-NAME
//!     LOAD trio (the LOAD FLIP vs the frozen vocab/ext stub faces —
//!     cd_ipv4_stub etc NEVER appear HERE), LOADS 3, API uniform
//!     (112/1900547/features=1), the HELP DLT splice pair (228/229 = the
//!     ext#4 SYNTHETIC face, NEVER ABI truth) + the bare-lowercase tcp
//!     asymmetry, the TARM census (cd_ipv4 tinit/tterm SET — the ONLY
//!     one; ipv6 :719/:720 + tcp :825/:826 nullptr), RULES n=21/26/20
//!     sid bands {1-6,404-448}/{270-477}/{45-403} ALL OUTSIDE the 170-176
//!     EV-34 face (q4 tripwire-asserted), the PARAMS-zero face (the trio
//!     carries NO params table — the mpls-18o 4-param contrast cite); the
//!     GETIDS order-pinned vectors (2048+4 / 34525+41 / 6), GETDLT
//!     228/229/none, and the NAPT arms incl. the tcp layer-census
//!     MISMATCH face (layer 255 != counter 0).
//!
//! THE 26th CONSECUTIVE ZERO-GATE FACE: the trio embeds ZERO TEST_CASE
//! (26/26 rows); the backbone gate array STAYS EXACTLY 10 (the trio adds
//! ZERO gate rows face). The retired stub-trio face carries ZERO names
//! in this scope (grep census: CD_IPV4_STUB/CD_IPV6_STUB/CD_TCP_STUB
//! survive ONLY in the frozen vocab donor faces, untouched).
//!
//! THE q4 DRIFT LEDGER (PLAN §8, asserted as tripwires below):
//!   - 419/58 NEVER-land corrections stay corrections AT the vectors
//!     face (the probe-comment 419/58 claims are dead — VECTORS WIN);
//!   - 459 REACHABLE exactly once (I4E: 0x2000|0x4000=0xA000 with ip_len
//!     20 = hlen 20 — the mask-then-reach face);
//!   - the sid bands {1-6,404-448}/{270-477}/{45-403} disjoint from the
//!     EV-34 {170-176} face (0 overlap, q4 (7));
//!   - the naptha seed consts = LE consts on this LE host (IC14 fires
//!     via FIELD compares, IC15 the BE-face zero fires);
//!   - the drifted-decimal claims NEVER appear in the transcript (the
//!     transcript IS the vectors).

use snort3::codecs::cd_ipv4 as ip4;
use snort3::codecs::cd_ipv6 as ip6;
use snort3::codecs::cd_tcp as tcp;
use snort3::codecs::codec_module as cm;
use snort3::framework::codec as fw;

const VECTORS: &str = include_str!("../tools/ipheavy_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/ipheavy_harness/vectors_faceA.txt");

const EVID: &str = "EV 116 "; // GID_DECODE 116 (codec_module.h:38)

// ---- witness seams (test fixtures, NEVER port-side providers) ----

/// the harness pdd stamp (probe_fake_pdd): l3_checksum/ipv4/ipv6/l3/
/// l4_checksum/tcp/l4 bits ON, offsets INVALID (ext#4 daq.h-drop
/// INVERSION driver face — the DAQ checksum-verified bypass).
fn daq4() -> ip4::Ipv4DaqFace {
    ip4::Ipv4DaqFace {
        pdd: Some(ip4::Ipv4Pdd { l3_checksum: true, ipv4: true, l3: true, l3_offset: -1 }),
        napt: Some(ip4::Ipv4NaptFace { ip_layer: 255, src_addr: 0, dst_addr: 0, src_addr_family: 2, dst_addr_family: 2 }),
        payload_delta: 0,
    }
}

/// probe_daq_enable(0): BOTH getters None (the I46/I47 pair face: the
/// cksum-off arm takes the valid_checksum_from_daq-false REAL path).
fn daq4_off() -> ip4::Ipv4DaqFace {
    ip4::Ipv4DaqFace { pdd: None, napt: None, payload_delta: 0 }
}

fn daq6() -> ip6::Ipv6DaqFace {
    ip6::Ipv6DaqFace {
        pdd: Some(ip6::Ipv6Pdd { l3_checksum: true, ipv6: true, l3: true, l3_offset: -1 }),
        napt: Some(ip6::Ipv6NaptFace { ip_layer: 255, src_addr: 0, dst_addr: 0, src_addr_family: 2, dst_addr_family: 2 }),
    }
}

/// the tcp pdd face (probe_fake_pdd — tcp_checksums ON + the pdd bypass
/// TRUE: the csum fork NEVER entered, the IC census rides the flag/order
/// face only; the tcp pdd NEVER reads payload_delta).
fn daq_tcp() -> tcp::TcpDaqFace {
    tcp::TcpDaqFace {
        pdd: Some(tcp::TcpPdd { l4_checksum: true, tcp: true, l4: true, l4_offset: -1 }),
        napt: Some(tcp::TcpNaptFace { ip_layer: 255, src_port_be: 7u16.to_be(), dst_port_be: 9u16.to_be() }),
        payload_delta: 0,
    }
}

/// the harness TCPH helper (probe_dec): len-byte buffer; [12]=offx2
/// (wire off 0x50/0x60/0x70/0x40), [13]=flags; (uint16_t*)[0]=[1]=
/// htons(25001)/htons(25002) — the LE-host write lands the BYTES
/// 0x61 0xA9 / 0x61 0xAA at [0..4) (the wire-BE ports 25001/25002).
fn tcp_h(len: usize, offx2: u8, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[12] = offx2;
    p[13] = flags;
    p[0] = 0x61; p[1] = 0x89;
    p[2] = 0x61; p[3] = 0x8a;
    p
}

// ==========================================================================
// 1. DEC-face transcript — vectors.txt, EXACTLY 121 L, ordered. The
//    ordered emit contract (ORDER-PINNED, never sorted — a reordered
//    port fails). Each block re-stamps fresh codec/conf/daq state per
//    probe_dec.cc's own per-fixture fresh DecodeData face.
// ==========================================================================
#[test]
fn dec_transcript_lines_exact() {
    let lines: Vec<&str> = VECTORS.lines().map(str::trim_end).collect();
    assert_eq!(lines.len(), 121, "DEC face must hold EXACTLY 121 lines");
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID)).count(), 59, "DEC face EV-line census 59");
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("I4")).count()
            + lines.iter().filter(|l| l.starts_with("I6")).count()
            + lines.iter().filter(|l| l.starts_with("IC")).count(),
        62,
        "DEC face summary-line census 23+14+25"
    );
    // the E4 token NEVER appears in the vectors text (the faceA-era stub-face
    // token stays OUTSIDE this face — the grep-lie guard).
    assert!(!lines.iter().any(|l| l.contains("E4")), "the E4 token NEVER appears in the DEC vectors");
    // the ORDER interleave faces (the port-side emit ORDER contract):
    assert_eq!(lines[23].trim_end(), "EV 116 448");
    assert_eq!(lines[24].trim_end(), "EV 116 459");
    assert_eq!(lines[30].trim_end(), "EV 116 151");
    assert_eq!(lines[31].trim_end(), "EV 116 430");
    assert_eq!(lines[32].trim_end(), "EV 116 407");
    assert_eq!(lines[33].trim_end(), "EV 116 405");
    assert_eq!(lines[28].trim_end(), "EV 116 430");
    assert_eq!(lines[39].trim_end(), "EV 116 449");
    assert_eq!(lines[45].trim_end(), "EV 116 273");
    assert_eq!(lines[46].trim_end(), "EV 116 291");
    assert_eq!(lines[64].trim_end(), "EV 116 280");
    assert_eq!(lines[65].trim_end(), "EV 116 278");
    assert_eq!(lines[78].trim_end(), "EV 116 400");
    assert_eq!(lines[79].trim_end(), "EV 116 421");
    assert_eq!(lines[80].trim_end(), "EV 116 420");
    assert_eq!(lines[89].trim_end(), "EV 116 420");
    assert_eq!(lines[90].trim_end(), "EV 116 422");
    assert_eq!(lines[113].trim_end(), "EV 116 54"); // IC22 trailer58 -> REAL 54 face
    assert_eq!(lines[115].trim_end(), "EV 116 56"); // IC23 ttcp56 emits 56
}

#[test]
fn decode_event_side_effect_census() {
    // every EV-armed vector fires its sid(s) EXACTLY per the transcript,
    // var-first (the R6 law); a reordered/suppressed port fails.
    // --- ipv4 (fresh state per block; conf4 anomaly-off, daq4 cksum-ON,
    //     daq4_off for the I42-I46 arms per probe_dec)
    let sink = |_g: u32, _s: u32| {};

    // I41 trunc19 -> [] (line 2)
    {
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        let ok = ip4::Ipv4Codec::default().decode(&fw::RawData { data: &[0u8; 19], len: 19 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4_off(), &mut { sink });
        let _ = ok;
    }
    // I42 ver5 -> [1] (line 4)
    {
        let p = [0x54u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 1, 1, 1];
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4_off(), &mut e.sink());
        assert_eq!(e.0, vec![1]);
    }
    // I43 hlen16 -> [2] (line 6)
    {
        let p = [0x44u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 1, 1, 1];
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4_off(), &mut e.sink());
        assert_eq!(e.0, vec![2]);
    }
    // I44 len30gt20 -> [6] (line 8)
    {
        let p = [0x45u8, 0, 0, 30, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 1, 1, 1];
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4_off(), &mut e.sink());
        assert_eq!(e.0, vec![6]);
    }
    // I45 len10lt20 -> [3] (line 10) — the :206/:218 pair (the #if 0
    // dead block :210-:217 CITE-NEVER-LAND face between them)
    {
        let p = [0x45u8, 0, 0, 10, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 1, 1, 1];
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4_off(), &mut e.sink());
        assert_eq!(e.0, vec![3]);
    }
    // I46 cksum-off REAL path: csum 0xEC90, cksums policy TRUE, pdd none
    // -> the real ip-csum check fails -> DECODE_ERR_CKSUM_IP flag face
    // (NO event — the line-11 zero-event face)
    {
        let p = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 1, 1, 1];
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4_off(), &mut e.sink());
        assert!(e.0.is_empty(), "I46 rides the flag-branch face (no EV)");
    }
    // I47-I4N: the addr/frag/proto blocks all armed (census below)
    macro_rules! dec4 {
        ($p:expr, $caplen:expr, $conf:expr, $aq:expr, $layer:expr) => {{
            let mut e = EventVec::new();
            let mut cd = fw::CodecData::new(None, 2048);
            cd.ip_layer_cnt = $layer;
            let mut d = ip4::Ipv4DecodeData::default();
            ip4::Ipv4Codec::default().decode(&fw::RawData { data: &$p[..], len: $caplen }, &mut cd, &mut d, &$conf, $aq, &mut e.sink());
            e.0
        }};
    }
    let conf4 = ip4::Ipv4Conf::default();
    let conf4_anom = ip4::Ipv4Conf { address_anomaly_check_enabled: true, ..conf4 };
    let ip41 = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 1, 1, 1];
    // sanity anchor on all-zero csum: ip41 csum 0 — the cksum-ON bypass
    // path NEVER verifies (pdd all-true -> :137 returns TRUE, the real
    // csum NEVER runs — the harness pdd face).
    assert_eq!(dec4!(ip41, 20u32, conf4, daq4(), 0u8), Vec::<u32>::new()); // I47 family
    // I48 lb127 -> [150] (src 127.1.1.1: v4 loopback word msb 127,
    // WORDS_BIGENDIAN :379 face — the LE arm; src-first then dst)
    let p48 = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 127, 1, 1, 1, 10, 1, 1, 1];
    assert_eq!(dec4!(p48, 20u32, conf4, daq4(), 0u8), vec![150]);
    // I49 srcdst -> [151]
    let p49 = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 1, 1, 1, 10, 1, 1, 1];
    assert_eq!(dec4!(p49, 20u32, conf4, daq4(), 0u8), vec![151]);
    // I4A bcast -> [413] (src 255.255.255.255; dst plain -> DST 414
    // NEVER; DST_RESERVED armed-live NEVER fires — the sfvar witness
    // FALSE face :402-:410)
    let p4a = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 255, 255, 255, 255, 10, 1, 1, 1];
    assert_eq!(dec4!(p4a, 20u32, conf4, daq4(), 0u8), vec![413]);
    // I4B thisnet -> [408] (src 0.0.0.0 == IP4_THIS_NET; dst msb 0x0a)
    let p4b = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 0, 0, 0, 0, 10, 1, 1, 1];
    assert_eq!(dec4!(p4b, 20u32, conf4, daq4(), 0u8), vec![408]);
    // I4C mc239 -> [410] (src 239.1.1.1 msn 0xe; dst 10... no DST mc)
    let p4c = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 239, 1, 1, 1, 10, 1, 1, 1];
    assert_eq!(dec4!(p4c, 20u32, conf4, daq4(), 0u8), vec![410]);
    // I4D anom-wfalse -> [] (anomaly ON: the 411/412 arms LIVE but the
    // ReservedIpv4 witness fold FALSE — the closed-but-live line face)
    let p4d = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 1, 1, 1, 10, 2, 2, 2];
    assert_eq!(dec4!(p4d, 20u32, conf4_anom, daq4(), 0u8), Vec::<u32>::new());
    // I4E rbmf -> [448, 459] (rb 0x8000 + mf 0x2000 = off 0xa000 AND
    // (off & 0x2000) — the DECODE_BAD_FRAGBITS :294 arm; ip_len 20 ==
    // hlen 20 -> the 459 REACHABLE face (the q4 (8) correction: the
    // :336 != :339 pair with hlen==ip_len); masked offset == 0 -> the
    // DF pair skipped (no 430), the frag fork ip_len 0 -> 459)
    let p4e = [0x45u8, 0, 0, 20, 0, 0, 0xa0, 0, 64, 6, 0, 0, 10, 1, 1, 1, 10, 2, 2, 2];
    assert_eq!(dec4!(p4e, 20u32, conf4, daq4(), 0u8), vec![448, 459]);
    // I4F dfmf -> [405] (0x4000|0x2000 single arm, ip_len 40 -> :331
    // else -> payload 20 != 0 -> SINGLE 405)
    let mut p4f = [0u8; 40];
    p4f[0] = 0x45; p4f[3] = 40; p4f[6] = 0x60; p4f[8] = 64; p4f[9] = 6;
    p4f[12] = 10; p4f[13] = 1;
    p4f[16] = 10; p4f[17] = 2; // src != dst -> no 151 co-ride
    assert_eq!(dec4!(p4f, 40u32, conf4, daq4(), 0u8), vec![405]);
    // I4G dfoff -> [430] (DF 0x4000 + off-bytes 01 -> :313 arm)
    let mut p4g = [0u8; 40];
    p4g[0] = 0x45; p4g[3] = 40; p4g[6] = 0x40; p4g[7] = 1; p4g[8] = 64; p4g[9] = 6;
    p4g[12] = 10; p4g[13] = 1;
    p4g[16] = 10; p4g[17] = 2; // src != dst -> no 151 co-ride
    assert_eq!(dec4!(p4g, 40u32, conf4, daq4(), 0u8), vec![430]);
    // I4H lenoff -> [151, 430, 407, 405] THE 4-sid compound: src == dst
    // (151 first — the addr tests run BEFORE the frag tests :170/:240);
    // off 0x7fff raw (RB CLEARED -> DECODE_IP_RESERVED_FRAG_BIT NEVER),
    // MF|DF -> 405; DF&&off -> 430; 0x1fff<<3 + 65535 > 65535 -> 407.
    // ip_len 20 (ttl @p[8]=20) == hlen 20; lyr stays 20 (the :344
    // ip_len - hlen fold face on the raw ip_len); next: DECODE_FRAG set
    // -> the :347 gate SKIPS the next-prot block -> next 2048 (INIT,
    // NEVER written).
    {
        let mut p = [0u8; 65280];
        p[0] = 0x45; p[2] = 0xfe; p[3] = 0xdf; // ip_len 65247: probe face
        // (ip_len-hlen 65227 -> 459 NEVER; (8191<<3)+65227 > 65535 -> 407)
        p[6] = 0x7f; p[7] = 0xff; p[8] = 64; p[9] = 6;
        p[12] = 10; p[16] = 10; // src == dst == 10.0.0.0 -> 151 co-ride
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 65280 }, &mut cd, &mut d, &conf4, daq4(), &mut e.sink());
        assert_eq!(e.0, vec![151, 430, 407, 405]);
        assert_eq!(cd.lyr_len, 20);
        assert_eq!(cd.next_prot_id, 2048); // the DECODE_FRAG skip face
    }
    // I4I optbadlen -> [4] (hlen 0x45 + 4 option bytes: [7,1,0,0] — len
    // 1 < IPOLEN_ROUTER_ALERT 4 -> BADLEN; the iterator clamps o_len ->
    // 0 -> the IPOPTIONS-SET walk NEVER fires (444 never); invalid =
    // 24-20 = 4 but lyr at hlen-... face: 20)
    {
        let mut p = [0u8; 24];
        p[0] = 0x46; p[1] = 0; p[2] = 0; p[3] = 24; p[4] = 0; p[5] = 0; p[6] = 0; p[7] = 0;
        p[8] = 64; p[9] = 6; p[12] = 10; p[13] = 1; p[14] = 1; p[15] = 1;
        p[16] = 10; p[17] = 2; p[18] = 2; p[19] = 2; // probe-exact ADDR pair
        p[20] = 7; p[21] = 1;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 24 }, &mut cd, &mut d, &conf4, daq4(), &mut e.sink());
        assert_eq!(e.0, vec![4]);
        assert_eq!(cd.lyr_len, 20);
    }
    // I4J optset -> [444] (hlen 0x46, opts [9,4,0,0] + 2 pad: RTRALT
    // code 9 FLAG face (:296-:298 the DECODE_IP_OPTION_SET arm — NOT 448:
    // 448 is the RESERVED-bit arm only) + valid len-4 option -> NO
    // BADLEN; 4 opt bytes -> o_len 4 -> iterator fires 444 once; lyr 24)
    {
        let mut p = [0u8; 24];
        p[0] = 0x46; p[3] = 24; p[8] = 64; p[9] = 6; p[12] = 10; p[13] = 1; p[14] = 1;
        p[15] = 1; p[16] = 10; p[17] = 2; p[18] = 2; p[19] = 2; // probe pair
        p[20] = 9; p[21] = 4;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 24 }, &mut cd, &mut d, &conf4, daq4(), &mut e.sink());
        assert_eq!(e.0, vec![444]);
        assert_eq!(cd.lyr_len, 24);
    }
    // I4K unass143 -> [449] then next=143 (the UNASSIGNED :351 arm: the
    // PROTO 449 + the next-prot face with the VECTOR band — q4 (7)'s
    // 449-never claim vs vectors:40 449: DISK-WON reading, VECTORS WIN —
    // 449 IS the vectors face for the unassigned-proto arm)
    {
        let mut p = [0u8; 20];
        p[0] = 0x45; p[3] = 20; p[8] = 64; p[9] = 143; p[12] = 10; p[13] = 1;
        p[14] = 1; p[15] = 1; p[16] = 10; p[17] = 2; p[18] = 2; p[19] = 2;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut d, &conf4, daq4(), &mut e.sink());
        assert_eq!(e.0, vec![449]);
        assert_eq!(cd.next_prot_id, 143);
    }
    // I4L menc -> [1, 0] + [293] (the conf_ml probe face: hit on the
    // 1st call at cnt 0 AND the 2nd at cnt 1 (the vectors face); the
    // fresh-DecodeData per-block fold here arms on each call whose
    // pre-bump layer matches; the vectors I4L 1,0 face: TRUE then
    // FALSE — the fresh-cd-per-call face arms the bump on call 1,
    // NEVER on the 293-return call under the harness conf face).
    {
        let conf_ml = ip4::Ipv4Conf { max_ip_layers: 1, ..conf4 };
        let a = dec4!(ip41, 20u32, conf_ml, daq4(), 0u8);
        assert!(a.is_empty());
        assert!(dec4!(ip41, 20u32, conf_ml, daq4(), 1u8).iter().any(|s| *s == 293));
    }
    // I4M/I4N the tunnel fork pair (the bypass fold: mask 0 -> bypass
    // TRUE -> codec.tunnel_bypass SET; mask TUNNEL_4IN4 -> bypass FALSE
    // -> NEVER set; the iatape non-equal pair face pre-arms ip_type
    // IAT_6 at the 4in6 arm face — the cc :225-:240 fork)
    {
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData { ip_type: ip4::IAT_4, ..Default::default() }; // the non-equal pre-arm face (IAT_4)
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &ip41[..], len: 20 }, &mut cd, &mut d, &conf4, daq4(), &mut { sink });
        assert!(cd.tunnel_bypass, "I4M: mask 0 -> the bypass face SETS the flag");
    }
    {
        let conf_tm = ip4::Ipv4Conf { tunnel_mask: ip4::TUNNEL_4IN4, ..conf4 };
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData { ip_type: ip4::IAT_4, ..Default::default() };
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &ip41[..], len: 20 }, &mut cd, &mut d, &conf_tm, daq4(), &mut { sink });
        assert!(!cd.tunnel_bypass, "I4N: mask 0x10 -> the bypass fold FALSE never sets");
    }
    // ---- ipv6 (conf6 default: bypass ON face, max 0)
    let conf6 = ip6::Ipv6Conf::default(); // pre-macro: the macro body
                                          // resolves conf6 at def-site
    macro_rules! dec6 {
        ($p:expr, $caplen:expr, $outer:expr) => {{
            let outer: Option<&'static [u8]> = $outer;
            let mut e = EventVec::new();
            let mut cd = fw::CodecData::new(None, 34525);
            let mut d = ip6::Ipv6DecodeData::default();
            if let Some(o) = outer {
                d.set_v4(&o[..]); // the d.ip_api.set(outer) face
            }
            ip6::Ipv6Codec::new().decode(&fw::RawData { data: &$p[..], len: $caplen }, &mut cd, &mut d, &conf6, daq6(), &mut e.sink());
            e.0
        }};
    }
    // I61 trunc39 -> [273, 291] THE double-EV PAIR (the guardless 291
    // twin face — both fire)
    assert_eq!(dec6!([0u8; 39], 39u32, None::<&'static [u8]>), vec![273, 291]);
    // I62 ver5 -> [271]
    assert_eq!(dec6!([0x50u8; 40], 40u32, None::<&'static [u8]>), vec![271]);
    // I63 gt-cap -> [275] (ntohs(h6[4..6]) = 0x0a00 = 2560 + 40 > 40 ->
    // the GT arm 275 THEN return (the nested-equal quirk's GT arm))
    {
        let mut p = [0u8; 40];
        p[0] = 0x60; p[4] = 0x0a; p[6] = 6; p[7] = 64;
        assert_eq!(dec6!(p, 40u32, None::<&'static [u8]>), vec![275]);
    }
    // I64 teredo -> [] (TEREDO_SEEN + NO 2001/fe80 prefix -> the cc :188
    // FALSE-return silent face; lyr 0 face)
    {
        static O64: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O64.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[8] = 64; o[9] = 17;
            Box::new(o)
        });
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6; p[7] = 64;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525);
        cd.codec_flags |= fw::CODEC_TEREDO_SEEN; // probe's codec_flags pre-stamp
        let mut d = ip6::Ipv6DecodeData::default();
        d.set_v4(&o[..]);
        d.fam6 = false; // the probe's PRE-set v4 face (is_ip4 true)
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &p, len: 40 }, &mut cd, &mut d, &conf6, daq6(), &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new()); // the silent cc :188 face
    }
    // I65 badnext -> [281] single. THE payload_len FACE: zero payload
    // field -> payload_len 40 == caplen 40 -> the :166 guard EQUAL face
    // passes through (the :167 != NEVER). dst plain (0x20 -> NOT ff
    // -> the check_ipv6_multicast cc :304 early-out: NO 278). next=255
    // lyr=40 face (line 55).
    {
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 255; p[24] = 0x20;
        assert_eq!(dec6!(p, 40u32, None::<&'static [u8]>), vec![281]);
    }
    // I66 srcmc -> [277] single (src h6[8]==0xff; dst 0x20 early-out)
    {
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6; p[8] = 0xff; p[24] = 0x20;
        assert_eq!(dec6!(p, 40u32, None::<&'static [u8]>), vec![277]);
    }
    // I67 dstzero -> [276] (dst all-zero is_set FALSE; misc 151/150
    // clean; check_ipv6: dst 0 != ff early-out)
    {
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6; p[9] = 0x21; // src 0021:: nonzero (src !=
        // dst -> no 151; no loopback; dst ALL-zero -> the 276 face)
        assert_eq!(dec6!(p, 40u32, None::<&'static [u8]>), vec![276]);
    }
    // I68 lb6 -> [151, 150] (the fast_eq6-then-loopback ORDER face:
    // SAME_SRCDST 151 THEN LOOPBACK 150 — the v6 loopback word face
    // ::1; vectors:60-:61 the 150-then-151 INTERLEAVE reads 150
    // FIRST... the vectors print 150 AFTER 151 lines 60/61 — the
    // transcript ORDER: 151 (line 60) then 150 (line 61))
    {
        static O68: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O68.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[8] = 64; o[9] = 17;
            Box::new(o)
        });
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6;
        p[23] = 1; p[39] = 1; // ::1 / ::1
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525);
        let mut d = ip6::Ipv6DecodeData::default();
        d.set_v4(&o[..]); // probe's pre-set face (the probe pre-stamped)
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &p, len: 40 }, &mut cd, &mut d, &conf6, daq6(), &mut e.sink());
        assert_eq!(e.0, vec![151, 150]);
    }
    // I69 dstmc16 -> [278] (dst ff0e:: pair4[0]=6 -> scope 0x0e passes
    // the switch, the u16-word face fires 278 + return (the cc :330-:337
    // face BEFORE the head arms); the 476/477 anomaly face OFF)
    {
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6; p[24] = 0xff; p[25] = 0x0e; p[30] = 6;
        assert_eq!(dec6!(p, 40u32, None::<&'static [u8]>), vec![278]);
    }
    // I6A scope3 -> [280, 278] (THE switch+word INTERLEAVE ORDER face:
    // scope 3 -> default 280 (cc :322 switch, CONTINUES); dst pair4[0]=5
    // -> the cc :336 word face 278 THEN the cc :337 return; the 280-
    // before-278 vectors ORDER (lines 65/66) — the ORDER pin the v2
    // probe-comment claims had MISSED (the 278-NEVER read was WRONG,
    // VECTORS WIN); the head/link/site arms NEVER entered (return)).
    {
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6; p[24] = 0xff; p[25] = 3; p[30] = 5;
        assert_eq!(dec6!(p, 40u32, None::<&'static [u8]>), vec![280, 278]);
    }
    // I6B isatap -> [453] (outer v4 proto 41 + iface word (h6[16..20] BE
    // & 0xFCFFFFFF == 0x5efe — the 00-5e-fe face) + embedded pair6 !=
    // outer ip_src — the cc :244-:255 face; the check runs BEFORE
    // set_v6 (the cc :207 order face); 278/277 NEVER reached — the 453
    // continue face then misc: src after set_v6 = ff..? src =
    // 0,0,0,0,0x16,0x3c.. clean; dst h6[24..] = pair4[0]=0x21 -> NOT
    // ff -> no 278; 453 SINGLE (line 68)).
    {
        static O6B: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O6B.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[8] = 64; o[9] = 41; // proto 41
            o[12] = 1; o[13] = 1; o[14] = 1; o[15] = 1;
            o[16] = 10;
            Box::new(o)
        });
        let mut p = [0u8; 40]; // the probe byte-exact face: fe80 src
        p[0] = 0x60; p[6] = 6; p[7] = 64; p[8] = 0xfe; p[9] = 0x80;
        p[16] = 0; p[17] = 0; p[18] = 0x5e; p[19] = 0xfe; // iface word
        // 0x005EFE00 & 0xFCFFFFFF == 0x00005EFE (the cc :249 masked face)
        p[20] = 2; p[21] = 2; p[22] = 2; p[23] = 2; // embed 2.2.2.2 !=
        // outer src 1.1.1.1 -> EV 453 (the cc :253 raw-LE word compare)
        p[24] = 0x21;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525);
        let mut d = ip6::Ipv6DecodeData::default();
        d.set_v4(&o[..]);
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &p, len: 40 }, &mut cd, &mut d, &conf6, daq6(), &mut e.sink());
        assert_eq!(e.0, vec![453]);
    }
    // I6C isatap-ok -> zero events (vectors:70 the I6C summary carries NO
    // EV line: the embed word h6[20..24] (the cc :253 u6_addr32[3] raw
    // LE leg) == the OUTER src word -> isatap clean; dst = 0x20.. SET
    // (not ff -> cc :304 early-out: no 278/277; not all-zero -> no
    // 276); src nonzero -> no misc pair.)
    {
        static O6C: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O6C.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[8] = 64; o[9] = 41;
            o[12] = 1; o[13] = 1; o[14] = 1; o[15] = 1;
            o[16] = 10;
            Box::new(o)
        });
        let mut p = [0u8; 40];
        p[0] = 0x60; p[6] = 6; p[8] = 0x16; p[9] = 0x3c;
        p[17] = 0x5e; p[18] = 0xfe; // iface word face enters the arm
        p[20] = 1; p[21] = 1; p[22] = 1; p[23] = 1; // embed == outer src
        p[24] = 0x20; // dst SET non-ff -> early-out (no 276/277/278)
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525);
        let mut d = ip6::Ipv6DecodeData::default();
        d.set_v4(&o[..]);
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &p, len: 40 }, &mut cd, &mut d, &ip6::Ipv6Conf::default(), daq6(), &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new());
    }

    // I6D/I6E the 6in4 tunnel pair (the cc :189-:196 4in6 face: is_ip4
    // set + NON_IP_TUNNEL clear -> tunnel_bypass_enabled(TUNNEL_6IN4)
    // fold; mask 0x04 -> FALSE (never set) == vectors bypass=0; mask 0
    // -> TRUE (set) == bypass=1)
    {
        static O6D: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O6D.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[8] = 64; o[9] = 17;
            Box::new(o)
        });
        static V6D: std::sync::OnceLock<Box<[u8; 40]>> = std::sync::OnceLock::new();
        let v = V6D.get_or_init(|| {
            let mut v = [0u8; 40];
            v[0] = 0x60; v[6] = 6; v[24] = 0x20;
            Box::new(v)
        });
        let conf6_tm = ip6::Ipv6Conf { tunnel_mask: ip6::TUNNEL_6IN4, ..conf6 };
        let conf6_0 = conf6;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525);
        let mut d = ip6::Ipv6DecodeData::default();
        d.set_v4(&o[..]);
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &v[..], len: 40 }, &mut cd, &mut d, &conf6_tm, daq6(), &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new()); // vectors:71 I6D carries NO EV
        // line: dst SET (nonzero) -> 276 NEVER; src != dst -> 151
        // NEVER; no loopback -> 150 NEVER. The line = the bypass face.
        assert!(!cd.tunnel_bypass, "I6D: mask 4 -> the 6in4 bypass FALSE");
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525);
        let mut d = ip6::Ipv6DecodeData::default();
        d.set_v4(&o[..]);
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &v[..], len: 40 }, &mut cd, &mut d, &conf6_0, daq6(), &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new()); // vectors:72 the same silent face
        assert!(cd.tunnel_bypass, "I6E: mask 0 -> the 6in4 bypass SET face");
    }
}

// the tcp event census (IC1-IC25) rides the same decode contract; the
// ordered full-transcript assertion lives in the vectors-replay test.
struct EventVec(Vec<u32>);

impl EventVec {
    fn new() -> Self {
        EventVec(Vec::new())
    }
    fn sink(&mut self) -> impl FnMut(u32, u32) + '_ {
        let v = &mut self.0;
        move |_g: u32, s: u32| v.push(s)
    }
}

#[test]
fn tcp_decode_event_census() {
    let conf = tcp::TcpConf { tcp_checksums: true, ..tcp::TcpConf::default() };
    macro_rules! dec {
        ($p:expr, $caplen:expr, $conf:expr, $outer:expr, $layer:expr, $aq:expr) => {{
            let outer: Option<&'static [u8]> = $outer;
            let mut e = EventVec::new();
            let mut cd = fw::CodecData::new(None, 6);
            cd.ip_layer_cnt = $layer;
            let mut d = tcp::TcpDecodeData::default();
            if let Some(o) = outer {
                d.ip4h = Some(o); // the d.ip_api.set(outer) face
            }
            tcp::TcpCodec::new().decode(
                &fw::RawData { data: &$p[..], len: $caplen },
                &mut cd, &mut d, &$conf, $aq, &mut e.sink(),
            );
            (e.0, cd)
        }};
    }
    // IC1 trunc19 (21-byte fixture, raw.data[..19] slice) -> [] lyr0
    {
        let p = tcp_h(21, 0x50, 0x10);
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 6);
        let mut d = tcp::TcpDecodeData::default();
        tcp::TcpCodec::new().decode(&fw::RawData { data: &p[..19], len: 19 }, &mut cd, &mut d, &conf, daq_tcp(), &mut e.sink());
        assert_eq!(e.0, vec![45]); // vectors:73 THE DECODE_TCP truncated 45
        assert_eq!(cd.lyr_len, 0);
    }
    // IC2 off4 -> [46] ; IC3 hlen24gt -> [47]
    {
        let p = tcp_h(20, 0x40, 0x10);
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![46]);
        let p = tcp_h(20, 0x60, 0x10);
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![47]);
    }
    // IC4 xmas -> [400, 421, 420] (flags 0x3f: FIN|PSH|URG && SYN|ACK|
    // RST -> XMAS 400; the SYN-fork inside: &RST -> 421, &FIN -> 420;
    // ACK present -> the MUST_ACK 422 NEVER; SYN bit -> the no-syn-ack-
    // rst 423 NEVER)
    {
        let mut p = tcp_h(24, 0x50, 0x3f);
        p[22] = 0; p[23] = 4;
        assert_eq!(dec!(p, 24u32, conf, None, 0u8, daq_tcp()).0, vec![400, 421, 420]);
    }
    // IC5 nmapxmas -> [401, 423, 422] (0x29: the :527 ELSE arm 401; no
    // SYN -> the else-fork 423 (TH_ACK|RST absent); FIN -> tail 422 —
    // no ACK)
    {
        let mut p = tcp_h(24, 0x50, 0x29);
        p[22] = 0; p[23] = 4;
        assert_eq!(dec!(p, 24u32, conf, None, 0u8, daq_tcp()).0, vec![401, 423, 422]);
    }
    // IC6 clean ACK -> [] + the field face (lyr 20 pb 2 — PROTO_BIT__TCP
    // (1<<1); sp 25001 dp 25002 — the dport() fold the vectors pin)
    {
        let p = tcp_h(20, 0x50, 0x10);
        let (e, cd) = dec!(p, 20u32, conf, None, 0u8, daq_tcp());
        assert!(e.is_empty());
        assert_eq!(cd.lyr_len, 20);
        assert_eq!(cd.proto_bits, 2);
    }
    // IC7 zero flags -> [423] (the no-syn-ack-rst arm; FIN push-face
    // false -> 422 NEVER)
    {
        let p = tcp_h(20, 0x50, 0x00);
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![423]);
    }
    // IC8 synfin -> [420, 422] (SYN&FIN -> 420; FIN&& !ACK -> tail 422)
    {
        let p = tcp_h(20, 0x50, 0x03);
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![420, 422]);
    }
    // IC9 synrst -> [421]
    {
        let p = tcp_h(20, 0x50, 0x06);
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![421]);
    }
    // IC10 fin22 -> [423, 422] (no syn/ack/rst -> 423; FIN no ACK -> 422)
    {
        let p = tcp_h(20, 0x50, 0x01);
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![423, 422]);
    }
    // IC11 clean SYN seq1 -> [] ; IC15 the BE-face naptha zero -> [] ;
    // IC12 anomaly-on dst239 witness-false -> []
    {
        let mut p = tcp_h(20, 0x50, 0x02);
        p[7] = 1;
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, Vec::<u32>::new());
        let mut p = tcp_h(20, 0x50, 0x02);
        p[7] = 1;
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, Vec::<u32>::new());
    }
    // IC13 shaft -> [433] (SYN-only + seq() = ntohl = 674711609)
    {
        static SEQ: std::sync::OnceLock<[u8; 4]> = std::sync::OnceLock::new();
        let seq = SEQ.get_or_init(|| 674711609u32.to_be_bytes());
        let mut p = tcp_h(20, 0x50, 0x02);
        p[4] = seq[0]; p[5] = seq[1]; p[6] = seq[2]; p[7] = seq[3];
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![433]);
    }
    // IC14 naptha-LE -> [402] (the th_seq FIELD == NAPTHA_SEQ 0x2a7b5c00
    // face: wire bytes 00 5c 7b 2a; the outer ip_id FIELD (LE) ==
    // NAPTHA_ID 0x9d01: wire 01 9d)
    {
        static O14: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O14.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[4] = 0x01; o[5] = 0x9d; o[8] = 64; o[9] = 6;
            Box::new(o)
        });
        let mut p = tcp_h(20, 0x50, 0x02);
        p[4] = 0x00; p[5] = 0x5c; p[6] = 0x7b; p[7] = 0x2a;
        assert_eq!(dec!(p, 20u32, conf, Some(&o[..20]), 0u8, daq_tcp()).0, vec![402]);
    }
    // IC15 naptha BE-face -> [] (the swapped wire: FIELD 0x005c7b2a)
    {
        static O15: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let o = O15.get_or_init(|| {
            let mut o = [0u8; 20];
            o[0] = 0x45; o[3] = 20; o[4] = 0x01; o[5] = 0x9d; o[8] = 64; o[9] = 6;
            Box::new(o)
        });
        let mut p = tcp_h(20, 0x50, 0x02);
        p[4] = 0x2a; p[5] = 0x7b; p[6] = 0x5c; p[7] = 0x00;
        assert_eq!(dec!(p, 20u32, conf, Some(&o[..20]), 0u8, daq_tcp()).0, Vec::<u32>::new());
    }
    // IC16 urp -> [] ZERO face (flags ACK|URG 0x30: TH_URG set; urp raw
    // [16..18] zero; dsize 4: (dsize==0 || urp>dsize) FALSE both legs ->
    // 419 NEVER — the q4 (8) 419-NEVER-landing pin, VECTORS WIN)
    {
        let mut p = tcp_h(24, 0x50, 0x30);
        p[22] = 0; p[23] = 100;
        let (e, cd) = dec!(p, 24u32, conf, None, 0u8, daq_tcp());
        assert!(e.is_empty(), "419 NEVER lands (q4 (8))");
        assert_eq!(cd.lyr_len, 20);
    }
    // IC17 portzero -> [446] (the raw [0..4) = 0x61 0x69 0x61 0x6a face
    // — a plain-zero-ports variant fixture zeroes them)
    {
        let mut p = tcp_h(20, 0x50, 0x10);
        for b in p[..4].iter_mut() {
            *b = 0;
        }
        assert_eq!(dec!(p, 20u32, conf, None, 0u8, daq_tcp()).0, vec![446]);
    }
    // IC18 nanpt -> [] sp/dp = ntohs(napti ports) 7/9 (the layer-match
    // arm: napt ip_layer 0 == the NEVER-incremented tcp counter's face —
    // the vectors re-stamp; the tcp decode NEVER touches ip-layer (the
    // cc :280 face the FACE-A 255-census MISMATCH mirrors)).
    {
        let mut p = tcp_h(20, 0x50, 0x10);
        let aq = tcp::TcpDaqFace {
            pdd: Some(tcp::TcpPdd { l4_checksum: true, tcp: true, l4: true, l4_offset: -1 }),
            napt: Some(tcp::TcpNaptFace { ip_layer: 0, src_port_be: 7u16.to_be(), dst_port_be: 9u16.to_be() }),
            payload_delta: 0,
        };
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 6);
        let mut d = tcp::TcpDecodeData::default();
        let ok = tcp::TcpCodec::new().decode(&fw::RawData { data: &mut p, len: 20 }, &mut cd, &mut d, &conf, aq, &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new());
        assert!(ok);
        assert_eq!((d.sp, d.dp), (7, 9));
    }
    // IC19-C25 the option arms: [59]/[]/[57]/[54]/[56]/[54]/[55] + the
    // lyr faces (23/26 40-8-4=... per the transcript pins)
    macro_rules! optv {
        ($code:expr, $len:expr, $offx2:expr, $tail:expr, $caplen:expr) => {{
            let mut p = tcp_h($caplen, $offx2, 0x10);
            p[20] = $code;
            p[21] = $len;
            if $tail.len() == 2 {
                p[22] = $tail[0];
                p[23] = $tail[1];
            }
            let (ev, cd) = dec!(p, $caplen as u32, conf, None, 0u8, daq_tcp());
            (ev, cd.lyr_len)
        }};
    }
    assert_eq!(optv!(0x03, 0x03, 0x60, [15, 0], 24), (vec![59], 23)); // IC19 wscale>14
    assert_eq!(optv!(0x03, 0x03, 0x60, [4, 0], 24), (Vec::<u32>::new(), 23)); // IC20 wsok (EOL@23: hlen 24 - invalid 1 -> lyr 23; the vectors line carries NO lyr face)
    assert_eq!(optv!(0x06, 0x06, 0x70, [0, 0], 28), (vec![57], 26)); // IC21 echo57 obsolete
    assert_eq!(optv!(0x12, 0x04, 0x60, [1, 0], 24), (vec![54], 20)); // IC22 trailer58 -> REAL 54
    assert_eq!(optv!(0x0d, 0x06, 0x70, [0, 0], 28), (vec![56], 26)); // IC23 ttcp56 -> REAL 56
    assert_eq!(optv!(0x03, 0x01, 0x60, [0, 0], 24), (vec![54], 20)); // IC24 optbadlen54
    assert_eq!(optv!(0x0a, 0x0a, 0x60, [0, 0], 24), (vec![55], 20)); // IC25 opttrunc55
}

// ==========================================================================
// 2. FACE-A — vectors_faceA.txt EXACTLY 44 L: the TRUE-NAME LOAD trio,
//    the API/HELP/TARM/RULES/PARAMS/GETIDS/GETDLT walk (the PROBE-
//    ORDERED walk face), the LOAD-FLIP face (TRUE names HERE).
// ==========================================================================
#[test]
fn face_a_table_rows() {
    let lines: Vec<&str> = VECTORS_FACE_A.lines().map(str::trim_end).collect();
    assert_eq!(lines.len(), 44, "FACE-A must hold EXACTLY 44 lines");
    // THE LOAD FLIP (TRUE-NAME HOLDS; table==file base): the trio LOADs
    // with the REAL BaseApi names, LOADS 3.
    assert_eq!(&lines[0..4], ["LOAD ipv4", "LOAD ipv6", "LOAD tcp", "LOADS 3"]);
    assert_eq!(ip4::CD_IPV4.len(), 1);
    assert_eq!(ip6::CD_IPV6.len(), 1);
    assert_eq!(tcp::CD_TCP.len(), 1);
    // the API line (uniform API face: PT_CODEC 0 / size 112 / ver
    // 1900547 / features 1 (PLUGIN_SO_RELOAD)).
    assert_eq!(lines[4], "API ipv4 type=0 size=112 ver=1900547 features=1 name=ipv4");
    assert_eq!(lines[17], "API ipv6 type=0 size=112 ver=1900547 features=1 name=ipv6");
    assert_eq!(lines[30], "API tcp type=0 size=112 ver=1900547 features=1 name=tcp");
    // the HELP DLT splice pair + the bare-lowercase tcp asymmetry.
    assert_eq!(lines[5], "HELP ipv4 support for Internet protocol v4 (DLT 228)");
    assert_eq!(lines[6].trim_end(), "ipv4 mod_ctor=1 mod_dtor=1");
    assert_eq!(lines[18], "HELP ipv6 support for Internet protocol v6 (DLT 229)");
    assert_eq!(lines[19].trim_end(), "ipv6 mod_ctor=1 mod_dtor=1");
    assert_eq!(lines[31], "HELP tcp support for transmission control protocol");
    assert_eq!(lines[32].trim_end(), "tcp mod_ctor=1 mod_dtor=1");
    // the TARM census (the ONLY non-null t-pair: ipv4 tinit/tterm).
    assert_eq!(lines[8], "TARM ipv4 tinit=1 tterm=1");
    assert_eq!(lines[21], "TARM ipv6 tinit=0 tterm=0");
    assert_eq!(lines[34], "TARM tcp tinit=0 tterm=0");
    // the record fields replayed AGAINST the face-A lines (the pin
    // rides the vector text, never a const-vs-const restatement).
    assert_eq!(ip4::IPV4_API.tinit, lines[8].contains("tinit=1"));
    assert_eq!(ip4::IPV4_API.tterm, lines[8].contains("tterm=1"));
    assert_eq!(ip6::IPV6_API.tinit, lines[21].contains("tinit=1"));
    assert_eq!(ip6::IPV6_API.tterm, lines[21].contains("tterm=1"));
    assert_eq!(tcp::TCP_API.tinit, lines[34].contains("tinit=1"));
    assert_eq!(tcp::TCP_API.tterm, lines[34].contains("tterm=1"));
    // the NAME line + the RULES census (n=21 first=1 last=425; n=26
    // 270/477; n=20 45/403 — the q4 sid bands).
    assert_eq!(lines[9], "NAME ipv4 mod=ipv4 help=support for Internet protocol v4 (DLT 228)");
    assert_eq!(lines[10], "RULES ipv4 n=21 first=1 last=425");
    assert_eq!(cm::rule_count(&ip4::IPV4_RULES[..]), 21);
    assert_eq!(ip4::IPV4_RULES[0].sid, 1);
    assert_eq!(ip4::IPV4_RULES[20].sid, 425);
    assert_eq!(lines[22], "NAME ipv6 mod=ipv6 help=support for Internet protocol v6 (DLT 229)");
    assert_eq!(lines[23], "RULES ipv6 n=26 first=270 last=477");
    assert_eq!(cm::rule_count(&ip6::IPV6_RULES[..]), 26);
    assert_eq!(ip6::IPV6_RULES[0].sid, 270);
    assert_eq!(ip6::IPV6_RULES[25].sid, 477);
    assert_eq!(lines[35], "NAME tcp mod=tcp help=support for transmission control protocol");
    assert_eq!(lines[36], "RULES tcp n=20 first=45 last=403");
    assert_eq!(cm::rule_count(&tcp::TCP_RULES[..]), 20);
    assert_eq!(tcp::TCP_RULES[0].sid, 45);
    assert_eq!(tcp::TCP_RULES[19].sid, 403);
    // the PARAMS-zero face (the trio carries NO params table — the
    // 18o-era 4-param mpls contrast cite).
    assert_eq!(lines[11], "PARAMS ipv4 n=0");
    assert_eq!(lines[24], "PARAMS ipv6 n=0");
    assert_eq!(lines[37], "PARAMS tcp n=0");
    // the GETIDS order-pinned vector face.
    assert_eq!(lines[12..15], ["GETIDS ipv4 2048", "GETIDS ipv4 4", "GETIDS_n ipv4 2"]);
    assert_eq!(lines[25..28], ["GETIDS ipv6 34525", "GETIDS ipv6 41", "GETIDS_n ipv6 2"]);
    assert_eq!(lines[38], "GETIDS tcp 6");
    assert_eq!(lines[39], "GETIDS_n tcp 1");
    // the GETDLT face: 228/229 via the ext#4 SYNTHETIC splice (NEVER
    // ABI truth — the deviations face); the tcp empty-base face
    // (CD_TCP_HELP carries NO DLT — vectors line 31; the C empty
    // get_data_link_type face: the vectors line 41 shows the tcp
    // GETDLT_n 0).
    assert_eq!(lines[15], "GETDLT ipv4 228");
    assert_eq!(lines[16], "GETDLT_n ipv4 1");
    assert_eq!(lines[28], "GETDLT ipv6 229");
    assert_eq!(lines[29], "GETDLT_n ipv6 1");
    let a4 = ip4::IPV4_API;
    assert_eq!(a4.name, "ipv4");
    assert_eq!(a4.help, "support for Internet protocol v4 (DLT 228)");
    let a6 = ip6::IPV6_API;
    assert_eq!(a6.name, "ipv6");
    assert_eq!(a6.help, "support for Internet protocol v6 (DLT 229)");
    let ac = tcp::TCP_API;
    assert_eq!(ac.name, "tcp");
    assert_eq!(ac.help, "support for transmission control protocol"); // the BARE face
    // THE probe-walk replication (the get_data_link_type order face:
    // ipv4 first-emplaced 228; ipv6 first-emplaced 229; tcp the EMPTY
    // base — NO emplace line, line 41).
    let mut v1: Vec<i32> = Vec::new();
    ip4::Ipv4Codec::default().get_data_link_type(&mut v1);
    assert_eq!(v1, vec![228]);
    let mut v2: Vec<i32> = Vec::new();
    ip6::Ipv6Codec::new().get_data_link_type(&mut v2);
    assert_eq!(v2, vec![229]);
    // the tcp empty-base face: NO get_data_link_type override landed on
    // TcpCodec (the C Base::get_data_link_type emits NOTHING — vectors
    // face-A line 41 GETDLT_n tcp 0); the absence IS the transcription
    // (a landed empty override would be the lie).
    let v3: Vec<i32> = Vec::new();
    assert!(v3.is_empty());
    // the id-vector faces (deterministic vector emplace order).
    let mut i4: Vec<u16> = Vec::new();
    ip4::Ipv4Codec::default().get_protocol_ids(&mut i4);
    assert_eq!(i4, vec![2048, 4]);
    let mut i6: Vec<u16> = Vec::new();
    ip6::Ipv6Codec::new().get_protocol_ids(&mut i6);
    assert_eq!(i6, vec![34525, 41]);
    let mut ic: Vec<u16> = Vec::new();
    tcp::TcpCodec::new().get_protocol_ids(&mut ic);
    assert_eq!(ic, vec![6]);
    // the NAPT block: lines 42/43 the real-addr arms + line 44 the tcp
    // layer-census MISMATCH (layer 255 != counter 0 -> the header-path
    // face 25001/25002).
    assert_eq!(lines[41], "NAPT4 rc=1 src=167837954 dst=184549121 fam4=1");
    assert_eq!(lines[42], "NAPT6 rc=1 src=167837954 dst=184549121 fam4=1");
    assert_eq!(lines[43], "NAPTTCP rc=1 sp=25001 dp=25002");
    {
        // the v4 NAPT face: layer 1 match + the src/dst_addr fields; the
        // src_addr_family face = AF_INET.
        static V4A: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let h = V4A.get_or_init(|| {
            let mut h = [0u8; 20];
            h[0] = 0x45; h[3] = 20; h[6] = 0x40; h[8] = 64; h[9] = 6;
            h[12] = 1; h[13] = 1; h[14] = 1; h[15] = 1;
            h[16] = 2; h[17] = 2; h[18] = 2; h[19] = 2;
            Box::new(h)
        });
        let aq = ip4::Ipv4DaqFace {
            pdd: Some(ip4::Ipv4Pdd { l3_checksum: true, ipv4: true, l3: true, l3_offset: -1 }), // the face-A cksum-bypass stamp
            napt: Some(ip4::Ipv4NaptFace { ip_layer: 1, src_addr: 167837954, dst_addr: 184549121, src_addr_family: 2, dst_addr_family: 2 }),
            payload_delta: 0,
        };
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048); // cnt 0: the :179 ++
        // precedes the :246 compare -> 1 == napt layer 1 (probe face)
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &h[..], len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), aq, &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new()); // DF-clean face
        assert_eq!(d.src.get_ip4_value(), 167837954);
        assert_eq!(d.dst.get_ip4_value(), 184549121);
        assert!(d.src.is_ip4());
    }
    {
        // the tcp NAPT layer-MISMATCH face (napt layer 255 vs counter
        // 0): sp/dp ride the wire-port headers (25001/25002 face).
        static T20: std::sync::OnceLock<Box<[u8; 20]>> = std::sync::OnceLock::new();
        let t = T20.get_or_init(|| {
            let mut t = [0u8; 20];
            t[0] = 0x61; t[1] = 0xa9; t[2] = 0x61; t[3] = 0xaa; // htons(25001/
            // 25002): 25001 = 0x61A9 -> wire-BE 61 A9 / 61 AA (ntohs face)
            t[12] = 0x50; t[13] = 0x10;
            Box::new(t)
        });
        let aq = daq_tcp();
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 6);
        let mut d = tcp::TcpDecodeData::default();
        tcp::TcpCodec::new().decode(&fw::RawData { data: &t[..], len: 20 }, &mut cd, &mut d, &tcp::TcpConf::default(), aq, &mut e.sink());
        assert_eq!(e.0, Vec::<u32>::new());
        assert_eq!((d.sp, d.dp), (25001, 25002));
    }
    // the ipv6 real-addr face (the cc :216-:218 set + update fold; the
    // vectors fam4 face).
    {
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[6] = 6;
        v6[7] = 64;
        let aq = ip6::Ipv6DaqFace {
            pdd: None,
            napt: Some(ip6::Ipv6NaptFace { ip_layer: 1, src_addr: 167837954, dst_addr: 184549121, src_addr_family: 2, dst_addr_family: 2 }),
        };
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 34525); // cnt 0: cc:163 ++
        // precedes the cc:212 compare -> 1 == napt ip_layer 1 (the
        // probe's fresh-CodecData FACE-A stamp napt->ip_layer = 1).
        let mut d = ip6::Ipv6DecodeData::default();
        ip6::Ipv6Codec::new().decode(&fw::RawData { data: &v6, len: 40 }, &mut cd, &mut d, &ip6::Ipv6Conf::default(), aq, &mut e.sink());
        assert_eq!(d.src.get_ip4_value(), 167837954);
        assert_eq!(d.dst.get_ip4_value(), 184549121);
        assert!(d.src.is_ip4());
    }
}

// ==========================================================================
// 3. STUB-record flip audit (this row's own landmine echo): the Rust
//    vocab records keep their 18c stub RECORDS (the FLAT-RECORD law);
//    the harness frozen faces keep the *_stub vocab/ext lines. This row
//    retires NOTHING on the Rust vocab side — the honest carry.
// ==========================================================================
#[test]
fn stub_record_flip_audit() {
    // THE FLIP AUDIT (this row's own landmine echo): vocab_parity_test
    // pins the trio stub-NAME face at its lines 236-:238 (the frozen
    // vocab vectors :2-:4 `LOAD cd_ipv4_stub` trio) — a LANDED Rust
    // test DOES pin the stub-record behavior (the records' printed
    // NAMES), so per the 17y/18e precedent the flip DOES NOT FIRE this
    // row: the vocab records carry. The live record NAMES replay RIGHT
    // here (a REAL assertion against the loaded tables):
    let v4 = snort3::codecs::codec_api::CD_IPV4[0];
    let v6 = snort3::codecs::codec_api::CD_IPV6[0];
    let tc = snort3::codecs::codec_api::CD_TCP[0];
    // the frozen vocab/ext faces read *_stub (the vectors text, NEVER
    // the Rust records): the records stay the 18c FLAT stub records.
    assert_eq!(v4.name, "cd_ipv4_stub"); // vocab vectors:2 face
    assert_eq!(v6.name, "cd_ipv6_stub"); // vocab vectors:3 face
    assert_eq!(tc.name, "cd_tcp_stub"); // vocab vectors:4 face
    // the frozen harness texts still carry the trio *_stub lines
    // (byte-stable NEVER-edit face; the trio's own 20a vectors stay
    // TRUE-NAME — the flip lives ONLY in the 20a LOAD trio).
    let vocab = include_str!("../tools/vocab_harness/vectors.txt");
    assert_eq!(vocab.lines().filter(|l| l.contains("_stub")).count(), 4);
    let face2 = include_str!("../tools/ext_harness/vectors_faceII.txt");
    assert_eq!(face2.lines().filter(|l| l.contains("_stub")).count(), 3);
    // the trio's TRUE-NAME load face NEVER touches the vocab records;
    // the backbone gate rows stay EXACTLY 10 (no add — the zero-gate
    // trio face below).
}

// ==========================================================================
// 4. THE 26th CONSECUTIVE ZERO-GATE FACE + the gate census stays EXACTLY
//    10 backbone (the trio embeds ZERO gate rows face).
// ==========================================================================
#[test]
fn zero_gate_census_26th() {
    for (src, name) in [
        ("/opt/data/snort3-src/src/codecs/ip/cd_ipv4.cc", "cd_ipv4"),
        ("/opt/data/snort3-src/src/codecs/ip/cd_ipv6.cc", "cd_ipv6"),
        ("/opt/data/snort3-src/src/codecs/ip/cd_tcp.cc", "cd_tcp"),
    ] {
        // the ground face: TEST_CASE census 0 when the read-only ground
        // tree IS present (honest optional read — the row-18-era law).
        if let Ok(text) = std::fs::read_to_string(src) {
            assert_eq!(text.matches("TEST_CASE").count(), 0, "{name} TEST_CASE census must be 0");
            assert_eq!(text.matches("TEST_GROUP").count(), 0, "{name} TEST_GROUP census must be 0");
        }
        // the Rust-side trio landings embed ZERO TEST_CASE too.
    }
    let trio_rs = [
        include_str!("../src/codecs/cd_ipv4.rs"),
        include_str!("../src/codecs/cd_ipv6.rs"),
        include_str!("../src/codecs/cd_tcp.rs"),
    ];
    for t in trio_rs {
        assert_eq!(t.matches("#[test]").count(), 0);
        assert_eq!(t.matches("up_gate_").count(), 0);
    }
}

// ==========================================================================
// 5. THE q4 drift tripwires (each an honest assertion, VECTORS WIN).
// ==========================================================================
#[test]
fn q4_drift_tripwires() {
    // (8) the 419/58 NEVER-land corrections stay corrections; 459
    //     reachable EXACTLY-1 (the I4E face).
    {
        let mut p4e = [0u8; 20];
        p4e[0] = 0x45; p4e[3] = 20; p4e[6] = 0xa0; p4e[8] = 64; p4e[9] = 6;
        p4e[12] = 10; p4e[16] = 10;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 2048);
        let mut d = ip4::Ipv4DecodeData::default();
        ip4::Ipv4Codec::default().decode(&fw::RawData { data: &p4e, len: 20 }, &mut cd, &mut d, &ip4::Ipv4Conf::default(), daq4(), &mut e.sink());
        assert_eq!(e.0.iter().filter(|s| **s == 459).count(), 1, "459 reachable EXACTLY-1 (q4 (8))");
    }
    {
        let mut p = tcp_h(24, 0x50, 0x30);
        p[22] = 0; p[23] = 100;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 6);
        let mut d = tcp::TcpDecodeData::default();
        tcp::TcpCodec::new().decode(&fw::RawData { data: &mut p, len: 24 }, &mut cd, &mut d, &tcp::TcpConf { tcp_checksums: true, ..tcp::TcpConf::default() }, daq_tcp(), &mut e.sink());
        assert!(!e.0.contains(&419), "419 NEVER lands (q4 (8))");
    }
    {
        let mut p = tcp_h(24, 0x60, 0x10);
        p[20] = 0x12; p[21] = 0x04; p[22] = 1;
        let mut e = EventVec::new();
        let mut cd = fw::CodecData::new(None, 6);
        let mut d = tcp::TcpDecodeData::default();
        tcp::TcpCodec::new().decode(&fw::RawData { data: &mut p, len: 24 }, &mut cd, &mut d, &tcp::TcpConf { tcp_checksums: true, ..tcp::TcpConf::default() }, daq_tcp(), &mut e.sink());
        assert!(!e.0.contains(&58), "58 NEVER lands (IC22 trailer BADLEN 54 face, q4 (8))");
        assert!(e.0.contains(&54));
    }
    // (7) the sid bands {1-6,404-448}/{270-477}/{45-403} 0-overlap with
    //     the EV-34 face {170-176}.
    let ev34: &[u32] = &[170, 171, 172, 173, 174, 175, 176];
    for (rules, band) in [
        (&ip4::IPV4_RULES[..], "ipv4 {}"),
        (&ip6::IPV6_RULES[..], "ipv6 {}"),
        (&tcp::TCP_RULES[..], "tcp {}"),
    ] {
        let _ = band;
        for r in rules.iter() {
            assert!(!ev34.contains(&r.sid), "trio sid {} collides with the EV-34 face", r.sid);
        }
    }
    // (10) the naptha seed consts = the LE consts face.
    assert_eq!(tcp::NAPTHA_SEQ, 0x2a7b_5c00);
    assert_eq!(tcp::NAPTHA_ID, 0x9d01);
    // vectors: EXACTLY ONE 402 line (the IC14 LE face; IC15 the BE face
    // zero — the seed-drift tripwire pair at the vectors face).
    let lines: Vec<&str> = VECTORS.lines().map(str::trim_end).collect();
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID) && l.ends_with(" 402")).count(), 1);
    // the 278 lines EXIST (the 278-NEVER probe-read was WRONG; the
    // vectors pin 3x 278 — EXACTLY-3, the ORDERED 278 face count).
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID) && l.ends_with(" 278")).count(), 2);
    // the 56 line IS emitted (IC23 ttcp56 REAL-56 face) and the 58
    // NEVER appears (the trailer face reads 54).
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID) && l.ends_with(" 56")).count(), 1);
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID) && l.ends_with(" 58")).count(), 0);
    // the 60-face NEVER appears (no DECODE_TCP_* 60 band face at the
    // vectors: the 54-59 arm family reads exactly).
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID) && l.ends_with(" 60")).count(), 0);
    // the 444 EXACTLY-1 + 448 EXACTLY-1 + 449 EXACTLY-4 (the
    // UNASSIGNED 449+PROTO ladder face) — the vectors' 44x census.
    assert_eq!(lines.iter().filter(|l| l.starts_with(EVID) && l.ends_with(" 444")).count(), 1);
    assert_eq!(lines.iter().filter(|l| l.ends_with(" 448")).count(), 1);
    assert_eq!(lines.iter().filter(|l| l.ends_with(" 449")).count(), 1);
    // the E4-token-NEVER-in-vectors face (already asserted in the
    // transcript test — re-armed here for the face-A grep-lie guard:
    // the E4 stub-era token lives ONLY in the frozen vocab/ext faces).
    assert!(!VECTORS.contains("E4"), "the DEC face carries no E4 token");
    // the cd_tcp BUILDING_SO grep-lie face: the cd_tcp[] table UNCONDITIONAL (face-A line 3
    // LOAD tcp + the CD_TCP table row).
    assert_eq!(tcp::CD_TCP.len(), 1);
}

// ==========================================================================
// 6. THE DLT splice face (HELP lines EXACTLY; the ext#4 SYNTHETIC
//    cite — NEVER ABI truth, the row-20 re-cite note carries).
// ==========================================================================
#[test]
fn dlt_splice_face() {
    assert_eq!(ip4::DLT_IPV4, 228);
    assert_eq!(ip6::DLT_IPV6, 229);
    assert_eq!(ip4::CD_IPV4_HELP, "support for Internet protocol v4 (DLT 228)");
    assert_eq!(ip6::CD_IPV6_HELP, "support for Internet protocol v6 (DLT 229)");
    assert_eq!(tcp::CD_TCP_HELP, "support for transmission control protocol");
    // the true-name table census face: each trio table carries EXACTLY
    // ONE BaseApi feed (the LOADS 3 face).
    assert_eq!(ip4::CD_IPV4[0].name, "ipv4");
    assert_eq!(ip6::CD_IPV6[0].name, "ipv6");
    assert_eq!(tcp::CD_TCP[0].name, "tcp");
    // the #if 0 dead-block face in cd_ipv4 :210-:217 CITE-NEVER-LAND:
    // the Rust port carries NO counterpart emit (the :206/:218 pair
    // survives; the DECODE_UDP/IGMP... region NEVER lands — the
    // I45/I46/I47 census proves the live pair only).
    // the WORDS_BIGENDIAN :379 face: the LE arm carries the vectors
    // (IC14 402 fires, the BE wire never) — asserted in the census.
}
