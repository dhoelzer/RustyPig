//! Parity test for the row-18i DAQ TRIO ports — three ground TUs
//! (ip/cd_udp.cc 660 L 3c60f0f788de2da7c1d196b694d969a5 / ip/cd_icmp4.cc
//! 645 L 12c1935ede670171715aeb970da42cc5 / ip/cd_icmp6.cc 518 L
//! 778157526e26f194e8ca832290ce164e; wc+md5+the 660+645+518=1823 SUM
//! re-measured and asserted EVERY build by tools/daq3_harness/build.sh
//! :38-:47). ZERO-gate row (the small4 ZERO-gate clone): combined gate
//! grep 0 x3 re-asserted every build -> this suite carries NO
//! up_gate_* set: honest absence, census-cited.
//!
//! Ground truth #1: `tools/daq3_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 93 L NEVER edited. WHOLE transcript replays HERE
//! line-for-line as ONE ordered session (per-index assert_eq over
//! want.len()==93). THE R6 EVAL-ORDER RULE REPLAYS: every decode bool
//! is stored BEFORE the summary line, and every `EV 116 <sid>` lands
//! BETWEEN the decode call and its summary printf, NEVER sorted. The
//! interleaves that pin order: :29/:30 (434+435 before enum666),
//! :34/:35 (416 BEFORE 440 — AddrTests runs on case ECHO_4 then falls
//! into ECHOREPLY's misc switch), :78/:79 (287+289 before rs-bad),
//! :81/:82 (288+290 before ra-bad).
//!
//! THE ROW'S DUAL-FACE HEADLINE (vectors:9/:10/:11 + :26/:27/:28 +
//! :68/:69): the SAME bad-checksum packet reads dflags=4/8 with the
//! DAQ meta OFF (the real checksum path, DECODE_ERR_CKSUM_UDP/ICMP
//! decode_data.h:133/:134) vs decode-SUCCEEDS dflags=0 with the
//! SYNTHETIC DAQ-valid pdd — valid_checksum_from_daq true -> the
//! checksum arm SKIPPED, the checksum_bypassed PEG rides
//! (cite-never-land; NOT the tunnel_bypass hook, the 18h correction).
//! The gate face udp_checksums()==1 prints LIVE from the LANDED
//! main/policy.rs NetworkPolicy::default (the witness pins the ground
//! NSDMI face policy.h:233 the same way, witness_daq.cc).
//!
//! Ground truth #2: `tools/daq3_harness/vectors_faceA.txt` — the
//! FACE-A load/walk face (probe.cc, ONE probe x THREE tables through
//! the in-probe PluginManager witness), 13 L, md5-pinned by the
//! harness. THE ipv6_api DRIFT RIDER (PLAN 3): the face prints NAME
//! icmp6 while the C api STRUCT is ipv6_api (cd_icmp6.cc:488) — the
//! Rust record const lands as IPV6_API carrying name "icmp6" (the
//! cd_auth/AH_API precedent); the file-base+api token is a FALSE-CLEAN
//! 0-hit grep face on both trees (build.sh drift tripwire).
//!
//! The DAQ legs ride the three ports' row-scoped seam types (DaqPdd/
//! DaqNapt/DaqFace, the graft copy/daq.h shapes — SYNTHETIC, NEVER
//! ABI, the harness daq.h-absence tripwired every build): the probe's
//! probe_fake_pdd/probe_fake_napt faces land as Some(...) args, the
//! probe_daq_enable(0) arm as None, the cc:271 pointer-difference as
//! the explicit offset arg (the payload-delta face witness_daq.cc
//! fake_payload).

use snort3::codecs::cd_icmp4 as icmp4;
use snort3::codecs::cd_icmp6 as icmp6;
use snort3::codecs::cd_udp as udp;
use snort3::codecs::codec_api as capi;
use snort3::codecs::codec_module as cm;
use snort3::framework::codec as fw;
use snort3::main::policy::NetworkPolicy;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/daq3_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/daq3_harness/vectors_faceA.txt");

fn buf4096() -> [u8; 4096] {
    [0u8; 4096]
}

/// probe_dec.cc:32 set_ip4: b zeroed, b[0]=0x45, b[12]=10, b[16]=20,
/// b[9]=17 — the 20-byte wire window the row seams carry verbatim
/// (leaked for the 'static window seam; test-only, no global state).
fn leaked_ip4_window() -> &'static mut [u8; 20] {
    let b = Box::leak(Box::new([0u8; 20]));
    b[0] = 0x45;
    b[12] = 10;
    b[16] = 20;
    b[9] = 17;
    b
}
/// probe_dec.cc:31 set_ip6: b6 zeroed, b6[0]=0x60.
fn leaked_ip6_window() -> &'static mut [u8; 40] {
    let b = Box::leak(Box::new([0u8; 40]));
    b[0] = 0x60;
    b
}

/// witness_daq.cc + probe_dec.cc:67-:69: the pinned synthetic-valid pdd
/// face (all guard bits set, l4_offset = DAQ_PKT_DECODE_OFFSET_INVALID).
fn valid_pdd() -> udp::DaqPdd {
    udp::DaqPdd {
        l4_checksum: true,
        udp: true,
        icmp: true,
        l4: true,
        l4_offset: udp::DAQ_PKT_DECODE_OFFSET_INVALID,
    }
}

/// probe_dec.cc:72: napt pinned ONCE for all daq-on arms —
/// src_port=htons(3000), dst_port=htons(6000), ip_layer 0 == the fresh
/// CodecData ip_layer_cnt 0 (cc:421; the ports' DaqNapt stores wire-BE,
/// ntohs'd at cc:423-:424).
fn pinned_napt() -> udp::DaqNapt {
    udp::DaqNapt {
        src_port_be: 3000u16.to_be(),
        dst_port_be: 6000u16.to_be(),
        ip_layer: 0,
    }
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 93 lines, ordered,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored).
// ==========================================================================
#[test]
fn daq3_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 93, "vectors.txt must hold the full 93-line DEC ladder");

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
    // witness_daq.cc:43-:50 get_network_policy pinned face == the landed
    // NetworkPolicy::default (checksum_eval = ALL|DEF, policy.h:233) —
    // all three inline gates read it (cc:367/:159/:197).
    let netpol = NetworkPolicy::default();

    // probe's `extern const snort::BaseApi* cd_*[]` + ctor(nullptr):
    // the table[0] record + the mod-less default-config ctor (cc:618-
    // :625 face; the udp twin via cd_udp::ctor(None)).
    let uc = udp::ctor(None); // ua->ctor(nullptr), probe_dec.cc:46
    let ic = icmp4::Icmp4Codec::new(); // ia->ctor(nullptr) probe_dec.cc:111
    let sc = icmp6::Icmp6Codec::new(); // sa->ctor(nullptr) probe_dec.cc:184

    // ---- UDP: the length-guard ladder (cc:318/:325/:333/:340) ----
    // vectors:1/:2 — probe_raw (nullptr,z,7): the z[4096] buffer face.
    {
        let z = buf4096();
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP short7 -> {}", b as u8));
    }
    {
        let p = [0u8; 12]; // p[4]=0,p[5]=4 -> uh_len 4 < 8 -> cc:325 EV 96
        let mut p = p;
        p[5] = 4;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP badlen4 -> {}", b as u8));
    }
    {
        let mut p = [0u8; 12]; // uh_len 20 > raw.len 12 -> cc:333 EV 97
        p[5] = 20;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP uhlen20 -> {}", b as u8));
    }
    {
        let mut p = [0u8; 12]; // uh_len 10 < raw.len 12 -> cc:340 EV 98
        p[5] = 10;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP uhlen10 -> {}", b as u8));
    }
    // DUAL FACE, ONE PACKET (uh_chk 0xFFFF fold-invalid, uh_len == raw.len):
    // D-arms: daq-OFF -> gate cc:367 true (witness NSDMI face) -> the real
    // path -> DECODE_ERR_CKSUM_UDP (decode_data.h:133 = 4); gate printed LIVE.
    {
        let mut p = [0u8; 12];
        p[0] = 0x22;
        p[1] = 0x23;
        p[2] = 0x22;
        p[3] = 0x23;
        p[5] = 12;
        p[6] = 0xFF;
        p[7] = 0xFF;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        // probe_daq_enable(0): meta OFF -> get_meta nullptr -> pdd None.
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!(
            "UDP cksumbad-daqoff -> {} dflags={} gate={}",
            b as u8,
            d.decode_flags,
            netpol.udp_checksums() as u8
        ));
    }
    // E-arm: same packet, synthetic DAQ-valid pdd -> valid_from_daq TRUE
    // -> the checksum arm SKIPPED (checksum_bypassed PEG cite-never-land).
    {
        let mut p = [0u8; 12];
        p[0] = 0x22;
        p[1] = 0x23;
        p[2] = 0x22;
        p[3] = 0x23;
        p[5] = 12;
        p[6] = 0xFF;
        p[7] = 0xFF;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(
            &raw,
            &mut cd,
            &mut d,
            &netpol,
            udp::DaqFace {
                pdd: Some(valid_pdd()),
                napt: Some(pinned_napt()),
                payload_delta: 0,
            },
            &mut sink,
        );
        push(format!(
            "UDP cksumbad-daqvalid -> {} dflags={} next={}",
            b as u8, d.decode_flags, cd.next_prot_id
        ));
    }
    // offset-mismatch fallback: l4_offset 0 != the payload delta ->
    // valid_from_daq FALSE -> SAME flag face as daq-OFF (vectors:11).
    {
        let mut p = [0u8; 12];
        p[0] = 0x22;
        p[1] = 0x23;
        p[2] = 0x22;
        p[3] = 0x23;
        p[5] = 12;
        p[6] = 0xFF;
        p[7] = 0xFF;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let pdd = udp::DaqPdd {
            l4_offset: 0, // probe f->l4_offset=0 (stack p != fake_payload)
            ..valid_pdd()
        };
        let b = uc.decode(
            &raw,
            &mut cd,
            &mut d,
            &netpol,
            udp::DaqFace {
                pdd: Some(pdd),
                napt: Some(pinned_napt()),
                payload_delta: 0x1000, // != 0 (the probe pointer delta face)
            },
            &mut sink,
        );
        push(format!("UDP daqoffsetmismatch -> {} dflags={}", b as u8, d.decode_flags));
    }
    // ip6 zero-checksum face (cc:392 EV 406, valid=false -> flag+false).
    {
        let mut p = [0u8; 12];
        p[5] = 12;
        let ip6h = leaked_ip6_window();
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let mut d = udp::UdpDecodeData {
            is_ip6: true,
            ip6h: Some(&*ip6h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP ip6zero -> {} dflags={}", b as u8, d.decode_flags));
    }
    // NAPT hit/miss pair (cc:420-:424): pinned napt ip_layer 0 == 0.
    {
        let mut p = [0u8; 12];
        p[0] = 0x22;
        p[1] = 0x23;
        p[2] = 0x22;
        p[3] = 0x23;
        p[5] = 12;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        // probe_daq_enable(1): pdd valid (bypass) + napt pinned above.
        let b = uc.decode(
            &raw,
            &mut cd,
            &mut d,
            &netpol,
            udp::DaqFace {
                pdd: Some(valid_pdd()),
                napt: Some(pinned_napt()),
                payload_delta: 0,
            },
            &mut sink,
        );
        push(format!("UDP napt-hit -> {} sp={} dp={}", b as u8, d.sp, d.dp));
    }
    {
        let mut p = [0u8; 12]; // ports 0 -> cc:481 EV 447 (UDPMiscTests)
        p[5] = 12;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        // probe_daq_enable(0): this buffer reads checksum-VALID in ground
        // (uh_chk 0 + the ip4 cc:373-:391 arith) — napt None rides the
        // cc:420 nullptr-meta arm.
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP naptmiss-portzero -> {} sp={} dp={}", b as u8, d.sp, d.dp));
    }
    {
        let mut z = buf4096(); // uh_len 4020 == raw -> pay 4012 > 4000 cc:478 EV 445
        z[1] = 1;
        z[2] = 15;
        z[3] = 196;
        z[4] = 0x0F;
        z[5] = 0xB4;
        let raw = fw::RawData { data: &z, len: 4020 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP large4020 -> {}", b as u8));
        for (i, v) in z.iter_mut().enumerate().take(18) {
            *v = 0;
            let _ = i;
        }
    }
    {
        let mut p = [0u8; 12]; // dst BE 3544 (0x0DD8) -> TEREDO next 257
        p[0] = 0x22;
        p[1] = 0x23;
        p[2] = 0x0D;
        p[3] = 0xD8;
        p[5] = 12;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
        let ip4h = leaked_ip4_window();
        let mut d = udp::UdpDecodeData {
            is_ip4: true,
            ip4h: Some(&*ip4h),
            ..Default::default()
        };
        let b = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
        push(format!("UDP teredo3544 -> {} next={}", b as u8, cd.next_prot_id));
    }
    {
        let mut v: Vec<fw::ProtocolId> = Vec::new();
        uc.get_protocol_ids(&mut v); // vectors:20 `UDPPID 17 n=1`
        push(format!("UDPPID {} n={}", v[0], v.len()));
    }
    {
        // probe: nb->mod_ctor(); rm=m->get_rules(); while(rm[n].sid) n++;
        let m = udp::UdpModule::new(); // vectors:21 `UDPRULES 7 sid0=95 name=udp`
        let rm = udp::UdpModule::get_rules();
        push(format!(
            "UDPRULES {} sid0={} name={}",
            cm::rule_count(rm),
            rm[0].sid,
            m.get_name()
        ));
    }

    // ---- ICMP4: 19 arms cover ALL 18 unique event names ----
    {
        let z = buf4096(); // RawData r(nullptr,z,3) — all-zero dgram
        _ = leaked_ip4_window(); // the b4 window face (icmp4 seams carry dst_ip4 only)
        let raw = fw::RawData { data: &z, len: 3 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, icmp4::DaqFace::default(), &mut sink);
        push(format!("ICMP4 short3 -> {}", b as u8));
    }
    let daq_on = icmp4::DaqFace {
        pdd: Some(icmp4::DaqPdd {
            l4_checksum: true,
            udp: true,
            icmp: true,
            l4: true,
            l4_offset: icmp4::DAQ_PKT_DECODE_OFFSET_INVALID,
        }),
        payload_delta: 0,
    };
    {
        let p = [3u8, 4, 0, 0]; // type3 code4 group, raw.len 4 < 8 -> cc:188 EV 105
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 type3-grp4 -> {}", b as u8));
    }
    {
        let p = [8u8, 0, 0xFF, 0xFF, 0, 0, 0, 0]; // daq-OFF fold-invalid -> flag 8 (cc:167)
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, icmp4::DaqFace::default(), &mut sink);
        push(format!("ICMP4 cksumbad-daqoff -> {} dflags={}", b as u8, d.decode_flags));
    }
    {
        let p = [8u8, 0, 0xFF, 0xFF, 0, 0, 0, 0]; // SAME packet daq-valid -> EV 434
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 cksumbad-daqvalid -> {} dflags={}", b as u8, d.decode_flags));
    }
    // probe_dec.cc:143 `probe_daq_enable(1);` — gate-skipped faces ride
    // daq_on for the rest of the icmp4 sweep (arm-dense, cksum field
    // irrelevant; the same DaqFace value re-passes — the C global switch
    // face folded into an explicit arg per the three ports' module docs).
    {
        let p = [8u8, 0, 0, 0, 0, 0, 0x9A, 0x02]; // seq 666 dsize 0 -> 434 + 435
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 enum666 -> {}", b as u8));
    }
    {
        let p = [8u8, 0, 0, 0, 0xAA, 0xBB, 0, 0, 0, 0, 0, 0]; // dsize 4 seq0 code0 -> EV 440
        // the set_ip4 b4 face: dst 20 rides the Icmp4DecodeData.dst_ip4 seam
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 smurf -> {}", b as u8));
    }
    {
        let p = [8u8, 0, 0, 0, 0xAA, 0xBB, 0, 0, 0, 0, 0, 0]; // dst 255.255.255.255 -> EV 416
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: icmp4::IP4_BROADCAST,
            ..Default::default()
        };
        let _ = leaked_ip4_window();
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 bcast -> {}", b as u8));
    }
    {
        let p = [8u8, 0, 0, 0, 0xAA, 0xBB, 0, 0, 0, 0, 0, 0]; // dst byte0 0xE0 -> EV 415 (cc:275-:282 LE arm)
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([0xE0, 0, 0, 0]), // w[16]=0xE0
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 mcast -> {}", b as u8));
    }
    {
        let p = [13u8, 0, 0, 0, 0, 0, 0, 0]; // type13 len 8 < 20 -> EV 106
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 tstamp8 -> {}", b as u8));
    }
    {
        let p = [17u8, 0, 0, 0, 0, 0, 0, 0]; // type17 len 8 < 12 -> EV 107
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 addr8 -> {}", b as u8));
    }
    {
        let p = [99u8, 0, 0, 0, 0, 0, 0, 0]; // default -> EV 418 THEN decode proceeds
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 type99 -> {}", b as u8));
    }
    {
        let p = [4u8, 0, 0, 0, 0, 0, 0, 0]; // source-quench -> len+4 next 259 + EV 439
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 sq8 -> {} next={}", b as u8, cd.next_prot_id));
    }
    {
        let p = [5u8, 1, 0, 0, 0, 0, 0, 0]; // redirect host -> EV 436
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 redirhost -> {}", b as u8));
    }
    {
        let p = [5u8, 0, 0, 0, 0, 0, 0, 0]; // redirect net -> EV 437
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 redirnet -> {}", b as u8));
    }
    {
        let p = [0u8, 0, 0, 0, 0, 0, 0, 0]; // echoreply + CODEC_IPOPT_RR_SEEN -> EV 438
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        cd.codec_flags |= 0x0010; // the codec.h :88 RR face (probe :195)
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 rr-echo -> {}", b as u8));
    }
    {
        let p = [3u8, 13, 0, 0, 0, 0, 0, 0]; // unreach code13 -> EV 441
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 unreach13 -> {}", b as u8));
    }
    {
        let p = [3u8, 10, 0, 0, 0, 0, 0, 0]; // -> EV 442
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 unreach10 -> {}", b as u8));
    }
    {
        let p = [3u8, 9, 0, 0, 0, 0, 0, 0]; // -> EV 443
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 unreach9 -> {}", b as u8));
    }
    {
        let p = [3u8, 4, 0, 0, 0, 0, 2, 0]; // FRAG_NEEDED mtu BE 512 < 576 -> EV 451 + next 259
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        push(format!("ICMP4 pmtu512 -> {} next={}", b as u8, cd.next_prot_id));
    }
    {
        let mut v: Vec<fw::ProtocolId> = Vec::new();
        ic.get_protocol_ids(&mut v); // vectors:62 `ICMP4PID 1 n=1`
        push(format!("ICMP4PID {} n={}", v[0], v.len()));
    }
    {
        let m = icmp4::Icmp4Module::new(); // vectors:63 `ICMP4RULES 25 sid0=105 name=icmp4`
        let rm = icmp4::Icmp4Module::get_rules();
        push(format!(
            "ICMP4RULES {} sid0={} name={}",
            cm::rule_count(rm),
            rm[0].sid,
            m.get_name()
        ));
    }

    // ---- ICMP6: the daq face + the ipv6_api drift ride (no api-name print) ----
    let daq6_on = icmp6::DaqFace {
        pdd: Some(icmp6::DaqPdd {
            l4_checksum: true,
            udp: true,
            icmp: true,
            l4: true,
            l4_offset: icmp6::DAQ_PKT_DECODE_OFFSET_INVALID,
        }),
        payload_delta: 0,
    };
    {
        let z = buf4096(); // RawData r(nullptr,z,3)
        let raw = fw::RawData { data: &z, len: 3 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, icmp6::DaqFace::default(), &mut sink);
        push(format!("ICMP6 short3 -> {}", b as u8));
    }
    {
        // NO ip6 set (probe omits set_ip6) -> the cc:189 get_ip6h None face.
        let z = buf4096();
        let raw = fw::RawData { data: &z, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData::default();
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, icmp6::DaqFace::default(), &mut sink);
        push(format!("ICMP6 noip6 -> {}", b as u8));
    }
    {
        let p = [128u8, 0, 0xFF, 0xFF, 0, 0, 0, 0]; // daq-OFF fold-invalid -> flag 8 (cc:209-:212)
        let i6 = &*leaked_ip6_window();
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(i6),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, icmp6::DaqFace::default(), &mut sink);
        push(format!("ICMP6 cksumbad-daqoff -> {} dflags={}", b as u8, d.decode_flags));
    }
    {
        let p = [128u8, 0, 0xFF, 0xFF, 0, 0, 0, 0]; // SAME packet daq-valid -> proceeds
        let i6 = &*leaked_ip6_window();
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(i6),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!(
            "ICMP6 cksumbad-daqvalid -> {} dflags={} lyr={}",
            b as u8, d.decode_flags, cd.lyr_len
        ));
    }
    {
        let p = [128u8, 0, 0, 0, 0xAA, 0xBB, 0, 0]; // ip6 mcast dst -> EV 432
        let b6 = leaked_ip6_window();
        b6[24] = 0xFF; // the AFTER-zeroing set face (probe :201)
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*b6),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 mcast -> {}", b as u8));
    }
    {
        let mut p = [2u8, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0]; // mtu BE 1024 < 1280 -> EV 285 + next 260
        p[7] = 0;
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let i6 = &*leaked_ip6_window();
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(i6),
            ..Default::default()
        };
        // probe b6 window carries NO 0xFF dst byte for this arm:
        let mut d = {
            d.ip6h = Some(&*leaked_ip6_window_clean());
            d
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!(
            "ICMP6 toobig1024 -> {} lyr={} next={}",
            b as u8, cd.lyr_len, cd.next_prot_id
        ));
    }
    {
        let p = [1u8, 2, 0, 0]; // UNREACH_INVALID -> EV 286
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 unreach2 -> {}", b as u8));
    }
    {
        let p = [1u8, 7, 0, 0]; // code7 > 6 -> EV 457
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 unreach7 -> {}", b as u8));
    }
    {
        let p = [133u8, 1, 0, 0, 0, 0, 0, 1]; // RS code1 -> 287 + reserved -> 289
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 rs-bad -> {}", b as u8));
    }
    {
        let mut p = [0u8; 20]; // RA code1 -> 288 + reachable>3600000 -> 290
        p[0] = 134;
        p[1] = 1;
        p[8] = 0xFF;
        p[9] = 0xFF;
        p[10] = 0xFF;
        p[11] = 0xFF;
        let raw = fw::RawData { data: &p, len: 20 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 ra-bad -> {}", b as u8));
    }
    {
        let mut p = [0u8; 24]; // RA opt type1 length0 -> EV 478 (cc:166 walk)
        p[0] = 134;
        p[16] = 1;
        p[17] = 0;
        let raw = fw::RawData { data: &p, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 ra-zerolen -> {}", b as u8));
    }
    {
        let p = [139u8, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // NODE_INFO code3 > 2 -> EV 460
        let raw = fw::RawData { data: &p, len: 20 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 nodeinfo3 -> {}", b as u8));
    }
    {
        let p = [2u8, 0, 0, 0]; // too-big dsize 2 < 8 -> EV 105 + FALSE
        let raw = fw::RawData { data: &p, len: 6 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 toobig6 -> {}", b as u8));
    }
    {
        let p = [200u8, 0, 0, 0]; // unknown type -> EV 431
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq6_on, &mut sink);
        push(format!("ICMP6 type200 -> {}", b as u8));
    }
    {
        let mut v: Vec<fw::ProtocolId> = Vec::new();
        sc.get_protocol_ids(&mut v); // vectors:92 `ICMP6PID 58 n=1`
        push(format!("ICMP6PID {} n={}", v[0], v.len()));
    }
    {
        let m = icmp6::Icmp6Module::new(); // vectors:93 `ICMP6RULES 13 sid0=427 name=icmp6`
        let rm = icmp6::Icmp6Module::get_rules();
        push(format!(
            "ICMP6RULES {} sid0={} name={}",
            cm::rule_count(rm),
            rm[0].sid,
            m.get_name()
        ));
    }

    assert_eq!(got_total(&out), 93, "replay must land exactly 93 lines");
    let got = out.borrow();
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

fn got_total(out: &RcOf) -> usize {
    out.borrow().len()
}
type RcOf = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

/// a FRESH zeroed-but-0x60 ip6 window per arm (the probe's `uint8_t
/// b6[40]={0}; set_ip6` per-block face — every ICMP6 arm re-declares
/// b6, so no 0xFF dst leak between arms).
fn leaked_ip6_window_clean() -> &'static mut [u8; 40] {
    leaked_ip6_window()
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 13 lines (probe.cc in-probe
//    load_plugins witness walking the THREE real tables).
// ==========================================================================
#[test]
fn daq3_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 13, "vectors_faceA.txt must hold the full 13-line walk");

    let mut got: Vec<String> = Vec::new();

    // the witness load face: for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name)
    for tab in [udp::CD_UDP, icmp4::CD_ICMP4, icmp6::CD_ICMP6] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
    }
    got.push("LOADS 3".to_string());

    // probe.cc nm[3] = { "udp", "icmp4", "icmp6" } — THE DRIFT RIDER:
    // every name prints its file base (NO ipv6_api appears ANYWHERE in
    // the transcript — the C struct identifier never reaches the record;
    // the Rust IPV6_API const rides that C spelling underneath, the
    // cd_auth/AH_API precedent, module doc of cd_icmp6.rs).
    let tabs = [udp::CD_UDP, icmp4::CD_ICMP4, icmp6::CD_ICMP6];
    let nm = ["udp", "icmp4", "icmp6"];
    for (tag, tab) in nm.iter().zip(tabs.iter()) {
        let a = tab[0];
        got.push(format!(
            "API {} type={} size={} ver={} name={}",
            tag, a.ptype, a.size, a.api_version, a.name
        ));
        got.push(format!("HELP {} {}", tag, a.help));
        got.push(format!(
            "{} mod_ctor={} mod_dtor={}",
            tag, a.mod_ctor as u8, a.mod_dtor as u8
        ));
    }

    assert_eq!(got.len(), 13);
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "faceA line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 3. STATIC_NAMES tripwire + THE ipv6_api drift face Rust-side.
// ==========================================================================
#[test]
fn daq3_static_names_drift() {
    // The extern ladder rows NEVER re-touch: the trio names are ALREADY
    // resident (build.sh pins codec_api.rs :112/:114/:128 verbatim).
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_udp"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp4"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp6"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18i adds NO new externs"
    );

    // THE DRIFT: table cd_icmp6 + NAME "icmp6" + C STRUCT ipv6_api — the
    // Rust record const lands as IPV6_API (the cd_auth AH_API precedent);
    // the NAME side is what the face prints.
    assert_eq!(icmp6::CD_ICMP6_NAME, "icmp6"); // cc:39
    assert_eq!(icmp6::IPV6_API.name, "icmp6"); // cc:488 struct, cc:497 name slot
    assert!(std::ptr::eq(icmp6::CD_ICMP6[0], &icmp6::IPV6_API)); // cc:513 feeds &ipv6_api.base // cc:513 feeds &ipv6_api.base

    // The pair-rider absence: cd_icmp4_ip/cd_icmp6_ip (codec_api.cc
    // :55/:57, loads :100/:102) are resident-but-UNLINKED until their
    // row — NOT in the Rust ladder (the completeness note, build.sh).
    // NOTE the RESIDENT face: the pair names ride the RUST ladder too
    // (codec_api.rs :113/:115) — extern-name residency, NOT a loaded
    // plugin; the UNLOADED face is C-side (build.sh pair note).
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp4_ip"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp6_ip"));

    // udp/icmp4: NO drift face (file base == table base == record, the
    // cd_grep TRUE-NAME posture): NAME sides ride the FACE-A replay.
    assert_eq!(udp::CD_UDP_NAME, "udp");
    assert!(std::ptr::eq(udp::CD_UDP[0], &udp::UDP_API));
    assert_eq!(icmp4::CD_ICMP4_NAME, "icmp4");
    assert!(std::ptr::eq(icmp4::CD_ICMP4[0], &icmp4::ICMP4_API));
}

// ==========================================================================
// 4. THE record census — the trio is mod-pair UNIFORM (contrast the 18h
//    small4 asymmetry 1/0/1/1): 112/1900547/PT_CODEC x3 + ctor/dtor set.
// ==========================================================================
#[test]
fn daq3_record_census() {
    for a in [udp::CD_UDP[0], icmp4::CD_ICMP4[0], icmp6::CD_ICMP6[0]] {
        assert_eq!(a.ptype, fw::PT_CODEC);
        assert_eq!(a.size, 112); // sizeof(CodecApi), the probe pin (faceA:5/:8/:11)
        assert_eq!(a.api_version, 1900547);
        assert_eq!(a.version, 0);
        assert_eq!(a.features, fw::PLUGIN_SO_RELOAD);
        assert_eq!(a.options, fw::API_OPTIONS);
        // THE trio-uniform mod PAIR (faceA:7/:10/:13 all mod_ctor=1):
        assert!(a.mod_ctor, "{} mod_ctor", a.name);
        assert!(a.mod_dtor, "{} mod_dtor", a.name);
        assert!(!a.pinit);
        assert!(!a.pterm);
        assert!(!a.tinit);
        assert!(!a.tterm);
        assert!(a.ctor);
        assert!(a.dtor);
    }
}

// ==========================================================================
// 5. THE rules census — the while(rm[n].sid) rule_count face (the
//    vectors:21/:63/:93 RULES lines).
// ==========================================================================
#[test]
fn daq3_rules_census() {
    assert_eq!(cm::rule_count(&udp::UDP_RULES), 7); // vectors:21 sid0=95
    assert_eq!(udp::UDP_RULES[0].sid, 95);
    // UDP_RULES carries 7 rows + terminator (the [RuleMap;8] C face).
    assert_eq!(udp::UDP_RULES.len(), 8);

    assert_eq!(cm::rule_count(&icmp4::ICMP4_RULES), 25); // vectors:63 sid0=105
    assert_eq!(icmp4::ICMP4_RULES[0].sid, 105);
    assert_eq!(icmp4::ICMP4_RULES.len(), 26);

    assert_eq!(cm::rule_count(&icmp6::ICMP6_RULES), 13); // vectors:93 sid0=427
    assert_eq!(icmp6::ICMP6_RULES[0].sid, 427);
    assert_eq!(icmp6::ICMP6_RULES.len(), 14);

    // the terminator face (RuleMap::default-style sid 0 at the tail):
    for (rules, n) in [
        (&udp::UDP_RULES[..], 7usize),
        (&icmp4::ICMP4_RULES[..], 25),
        (&icmp6::ICMP6_RULES[..], 13),
    ] {
        assert_eq!(rules[n].sid, 0, "terminator sid must be 0");
        assert!(rules[n].msg.is_none(), "terminator msg must be None");
    }
}

// ==========================================================================
// 6. UNIT: the DUAL-FACE headline arms standalone — the SAME packet,
//    D-DAQ-off dflags=4 vs E-DAQ-valid dflags=0 (vectors:9/:10/:11).
// ==========================================================================
#[test]
fn up_daq3_udp_dual_face() {
    let conf = SnortConfig::default();
    let netpol = NetworkPolicy::default();

    let packet = |p: &mut [u8; 12]| {
        p[0] = 0x22;
        p[1] = 0x23;
        p[2] = 0x22;
        p[3] = 0x23;
        p[5] = 12;
        p[6] = 0xFF;
        p[7] = 0xFF;
    };
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |gid: u32, sid: u32| evs.borrow_mut().push((gid, sid));

    let uc = udp::ctor(None);

    // D-DAQ-off: meta None -> the real checksum path -> dflags=4 + false.
    let mut p = [0u8; 12];
    packet(&mut p);
    let raw = fw::RawData { data: &p, len: 12 };
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
    let ip4h = leaked_ip4_window();
    let mut d = udp::UdpDecodeData {
        is_ip4: true,
        ip4h: Some(&*ip4h),
        ..Default::default()
    };
    let ok_d = uc.decode(&raw, &mut cd, &mut d, &netpol, udp::DaqFace::default(), &mut sink);
    assert!(!ok_d, "D: daq-off bad cksum -> false");
    assert_eq!(d.decode_flags, udp::DECODE_ERR_CKSUM_UDP); // 4 (decode_data.h:133)
    assert!(evs.borrow().is_empty(), "D writes flags, never an event");

    // E-DAQ-valid: synthetic pdd -> the WHOLE cc:367-:415 arm skipped.
    let mut e = udp::UdpDecodeData {
        is_ip4: true,
        ip4h: Some(&*ip4h),
        ..Default::default()
    };
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
    let ok_e = uc.decode(
        &raw,
        &mut cd,
        &mut e,
        &netpol,
        udp::DaqFace {
            pdd: Some(valid_pdd()),
            ..Default::default()
        },
        &mut sink,
    );
    assert!(
        ok_e,
        "E: the SAME packet decodes under the synthetic-valid pdd"
    );
    assert_eq!(e.decode_flags, 0, "E: NO cksum flag (the PEG face)");
    assert_eq!(cd.next_prot_id, 17);

    // offset-mismatch fallback: SAME flag face as D (vectors:11).
    let mut f = udp::UdpDecodeData {
        is_ip4: true,
        ip4h: Some(&*ip4h),
        ..Default::default()
    };
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::UDP);
    let pdd = udp::DaqPdd {
        l4_offset: 0,
        ..valid_pdd()
    };
    let ok_f = uc.decode(
        &raw,
        &mut cd,
        &mut f,
        &netpol,
        udp::DaqFace {
            pdd: Some(pdd),
            payload_delta: 0x1000,
            ..Default::default()
        },
        &mut sink,
    );
    assert!(!ok_f);
    assert_eq!(f.decode_flags, udp::DECODE_ERR_CKSUM_UDP);

    // the guard itself (cc:265-:275 legs, standalone): None -> false.
    assert!(!udp::UdpCodec::valid_checksum_from_daq(None, udp::DAQ_PKT_DECODE_OFFSET_INVALID, 0));
    let mut p2 = valid_pdd();
    p2.udp = false; // the cc:266 .udp bit (the twins' .icmp face differs)
    assert!(!udp::UdpCodec::valid_checksum_from_daq(
        Some(p2),
        udp::DAQ_PKT_DECODE_OFFSET_INVALID,
        0
    ));
}

// ==========================================================================
// 7. UNIT: the icmp4 arm-dense face — the 11-label 8-byte guard, the
//    pmtu512 fall-through next 259, the smurf EV 440, the rr-echo 438.
// ==========================================================================
#[test]
fn up_daq3_icmp4_arm_dense() {
    let conf = SnortConfig::default();
    let netpol = NetworkPolicy::default();
    let daq_on = icmp4::DaqFace {
        pdd: Some(icmp4::DaqPdd {
            l4_checksum: true,
            udp: true,
            icmp: true,
            l4: true,
            l4_offset: icmp4::DAQ_PKT_DECODE_OFFSET_INVALID,
        }),
        payload_delta: 0,
    };
    let ic = icmp4::Icmp4Codec::new();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |gid: u32, sid: u32| evs.borrow_mut().push((gid, sid));

    // one shared ip4 window (b4 face; dst 20, no addr events)
    let dwin = &&*leaked_ip4_window();

    let mut run = |p: &[u8], codec_flags: u16| -> (bool, u16, Vec<(u32, u32)>) {
        let raw = fw::RawData { data: p, len: p.len() as u32 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV4);
        cd.codec_flags |= codec_flags;
        let mut d = icmp4::Icmp4DecodeData {
            dst_ip4: u32::from_le_bytes([20, 0, 0, 0]),
            ..Default::default()
        };
        let b = ic.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        let fired = std::mem::take(&mut *evs.borrow_mut());
        (b, cd.next_prot_id, fired)
    };

    // the shared-105 rail (group guard cc:188): type3 group, 4-byte face.
    let (b, _, fired) = run(&[3u8, 4, 0, 0], 0);
    assert!(!b);
    assert_eq!(fired, vec![(116, 105)], "group guard -> EV 105");

    // fall-through pmtu: EV 451, NO return, then len+=4 next 0x0103.
    let (b, next, fired) = run(&[3u8, 4, 0, 0, 0, 0, 2, 0], 0);
    assert!(b);
    assert_eq!(fired, vec![(116, 451)]);
    assert_eq!(next, 259);

    // the smurf quartet face: dsize 4 seq0 code0 -> EV 440 (cc:317).
    let (b, _, fired) = run(&[8u8, 0, 0, 0, 0xAA, 0xBB, 0, 0, 0, 0, 0, 0], 0);
    assert!(b);
    assert_eq!(fired, vec![(116, 440)]);

    // the rr-echo face: CODEC_IPOPT_RR_SEEN 0x0010 -> EV 438 (cc:307).
    let (b, _, fired) = run(&[0u8, 0, 0, 0, 0, 0, 0, 0], 0x0010);
    assert!(b);
    assert_eq!(fired, vec![(116, 438)]);

    // EMBED rider identity (the v4 face: 0x0103 == 259, h:130).
    let _: () = {
        let v = icmp4::PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4;
        assert_eq!(v, 259);
    };
    let _ = dwin;
}

// ==========================================================================
// 8. UNIT: the icmp6 NDP-walk + embedded faces (vectors:72-:73/:76-:77/
//    :84-:85/:88-:89).
// ==========================================================================
#[test]
fn up_daq3_icmp6_ndp_walk() {
    let conf = SnortConfig::default();
    let netpol = NetworkPolicy::default();
    let daq_on = icmp6::DaqFace {
        pdd: Some(icmp6::DaqPdd {
            l4_checksum: true,
            udp: true,
            icmp: true,
            l4: true,
            l4_offset: icmp6::DAQ_PKT_DECODE_OFFSET_INVALID,
        }),
        payload_delta: 0,
    };
    let sc = icmp6::Icmp6Codec::new();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |gid: u32, sid: u32| evs.borrow_mut().push((gid, sid));

    let mut run = |p: &[u8]| -> (bool, u16, u16, Vec<(u32, u32)>) {
        let raw = fw::RawData { data: p, len: p.len() as u32 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ICMPV6);
        let mut d = icmp6::Icmp6DecodeData {
            ip6h: Some(&*leaked_ip6_window_clean()),
            ..Default::default()
        };
        let b = sc.decode(&raw, &mut cd, &mut d, &netpol, daq_on, &mut sink);
        let fired = std::mem::take(&mut *evs.borrow_mut());
        (b, cd.lyr_len, cd.next_prot_id, fired)
    };

    // RA option type1 length0 -> the walk's EV 478, decode PROCEEDS
    // (false -> break, cc:166/:171; vectors:84/:85 -> 1).
    let full = {
        let mut f = [0u8; 24];
        f[0] = 134; // RA
        f[16] = 1; // option type 1
        // f[17] = 0 -> the length-0 walk arm (cc:166 EV 478)
        f
    };
    let (b, _, _, fired) = run(&full);
    assert!(b);
    assert_eq!(fired, vec![(116, 478)]);

    // too-big MTU 1024 < 1280 -> EV 285 + lyr 8 + next 0x0104 = 260.
    let p = [2u8, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0];
    let (b, lyr, next, fired) = run(&p);
    assert!(b);
    assert_eq!(fired, vec![(116, 285)]);
    assert_eq!(lyr, 8);
    assert_eq!(next, 260);

    // unreach code 7 -> 457 (non-RFC-4443, > 6). probe p[8] face:
    let p = [1u8, 7, 0, 0, 0, 0, 0, 0];
    let (b, _, _, fired) = run(&p);
    assert!(b);
    assert_eq!(fired, vec![(116, 457)]);

    // toobig dsize 2 < 8 -> shared 105 rail THEN FALSE return (no tail).
    let p = [2u8, 0, 0, 0];
    let (b, _, _, fired) = run(&p);
    assert!(!b);
    assert_eq!(fired, vec![(116, 105)]);

    // the code face pairs (h:87/:92 + cc:263/:306 riders).
    assert_eq!(icmp6::icmp6_code::UNREACH_INVALID, 2);
    assert_eq!(icmp6::icmp6_code::ADVERTISEMENT, 0);
    assert_eq!(icmp6::icmp6_type::PACKET_TOO_BIG, 2);
    assert_eq!(icmp6::icmp6_type::ROUTER_ADVERTISEMENT, 134);
}