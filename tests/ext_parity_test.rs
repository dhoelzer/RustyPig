//! Parity test for the row-18e IPv6-extension-chain port — 5 ground
//! TUs (ip/cd_hop_opts.cc 143 + ip/cd_dst_opts.cc 134 + ip/cd_routing.cc
//! 163 + ip/cd_mobility.cc 143 + ip/cd_igmp.cc 138 = 721 L, every wc
//! re-measured in ext PLAN §0).
//!
//! Ground truth #1: `tools/ext_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 27 L NEVER edited, md5 da21842980d042d5871edeaaf502049e
//! (the -O0 == -O2 byte-ident pair re-verified by the harness build.sh
//! cmp arms, ext PLAN §3). WHOLE transcript replays HERE line-for-line
//! as ONE ordered session (the csum/vocab/eth/flog replay shape:
//! per-index assert_eq over want.len()==27 — ordered, never
//! set-membership). probe_dec.cc statement order == transcript order,
//! R6 var-before-printf posture mirrored (probe_dec.cc grep-pinned).
//!
//! Ground truth #2: `tools/ext_harness/vectors_faceA.txt` — the FACE-A
//! load face (probe.cc table walk over the five REAL tables through
//! the load_plugins witness), 9 L, md5 0fa79b534d2a598b2befb047c95c3579
//! — replayed as the SECOND ordered session (ext PLAN §3: BOTH faces
//! tracked; the FACE-II flip transcript is a build receipt, not a pin,
//! ext PLAN §4d).
//!
//! Ground truth #3: there is NO upstream suite to translate — the §0
//! census measured 0 TEST_CASE / 0 TEST_GROUP / 0 ^TEST( / 0 UNIT_TEST
//! on ALL FIVE row files (ext PLAN §0, re-asserted every build by
//! build.sh), and ip/test = checksum_test.cc + CMakeLists only (the
//! 18b CppUTest face, ZERO units inside row files). So this row
//! honestly ships ZERO up_gate_* mirrors — the absence itself is the
//! artifact, recorded in deviations row 18e with the census cite
//! (vocab-18c/eth-18d precedent). A fake Catch gate = the 17p
//! anti-pattern.
//!
//! Eval-order note (ext PLAN §3): every probe decode stores the bool
//! to a VAR before its printf reads post-decode fields (R6 replicated
//! at scratch FACE-A/DEC faces); the replay mirrors the EMITTED order:
//! EV lines land between the decode call and the summary line exactly
//! as the C witness printer's interleave does (queue_event EV-printer
//! rides eth stubs_18d.cc / the sink closure here).
//!
//! Quirk discipline (ext PLAN §3 + recon §6.4): the five decode
//! ladders are NEVER unified. Hopopts len-first, mobility maxopts-
//! first, routing triple-guard, dstopts EXCESS-without-return,
//! mobility bad-payl-returns-TRUE — each pinned by a cited vectors
//! line or a cited C line below (the ladder_order_never_unified test
//! is the face-discriminator pair).

use snort3::codecs::cd_dst_opts as dstc;
use snort3::codecs::cd_hop_opts as hopc;
use snort3::codecs::cd_igmp as igmpc;
use snort3::codecs::cd_mobility as mobc;
use snort3::codecs::cd_routing as routec;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/ext_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/ext_harness/vectors_faceA.txt");

/// probe_dec.cc:16 `uint8_t p[64]={0};` — ONE buffer reused across the
/// HOP arms with mutation order p[0]=0x06 (vec:13 setup) then p[1]=1
/// (vec:15 setup); q (probe_dec.cc:31 `uint8_t q[64]={0}` + q[0]=0x2b
/// q[2]=0) and m (probe_dec.cc:39, m[0]=60) are SEPARATE buffers,
/// exactly like the C. Verbatim posture.
fn buf64() -> [u8; 64] {
    [0u8; 64]
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 27 lines, ordered,
//    one session (probe_dec.cc statement order).
// ==========================================================================
#[test]
fn ext_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 27, "vectors.txt must hold the full 27-line DEC ladder");

    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };
    // the queue_event witness seam: `EV %u %u` — gid is the constexpr
    // GID_DECODE 116 (codec_module.h:38) that the REAL framework/
    // codec.cc codec_event uses (eth PLAN §2 lineage; ext PLAN §3).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };

    // probe_dec.cc:15 api() x5 in call order hopopts, dstopts, routing,
    // mobility, igmp — each an API line (type/size/ver/name) then a
    // HELP line tagged by the same label. vectors:1-:10.
    {
        let api = |push: &dyn Fn(String), tag: &str, r: &fw::CodecApiRecord| {
            push(format!(
                "API {} type={} size={} ver={} name={}",
                tag, r.ptype, r.size, r.api_version, r.name
            ));
            push(format!("HELP {} {}", tag, r.help));
        };
        api(&push, "hopopts", hopc::CD_HOP_OPTS[0]); // vectors:1-2
        api(&push, "dstopts", dstc::CD_DSTOPTS[0]); // vectors:3-4
        api(&push, "routing", routec::CD_ROUTING[0]); // vectors:5-6
        api(&push, "mobility", mobc::CD_MOBILITY[0]); // vectors:7-8
        api(&push, "igmp", igmpc::CD_IGMP[0]); // vectors:9-10
    }

    // -- HOP arms on buffer p (probe_dec.cc:16-:26) --
    let h = hopc::Ipv6HopOptsCodec::new(); // the ctor slot face (ha->ctor)
    let mut p = buf64();
    {
        // arm 0: RawData r0(p, 7) -> decode false: the len<8 guard
        // raises TRUNCATED 272 FIRST (maxopts never reached).
        // vectors:11-:12 `EV 116 272` + `HOP short7 -> 0`.
        let raw = fw::RawData { data: &p, len: 7 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::HOPOPTS);
        let a0 = h.decode(&raw, &mut cd, &mut sink); // R6: var first
        push(format!("HOP short7 -> {}", a0 as i32));
    }
    {
        // arm 1: p[0]=0x06 (TCP), len 8: full-write face + true via
        // the PAD1-walk CheckIPV6HopOptions return. vectors:13
        // `HOP ok8 -> 1 next=6 lyr=8 bits=65536 cnt=1 csumproto=6`
        // (65536 = PROTO_BIT__IP6_EXT 0x10000, decimal posture).
        p[0] = 0x06;
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::HOPOPTS);
        let a1 = h.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "HOP ok8 -> {} next={} lyr={} bits={} cnt={} csumproto={}",
            a1 as i32,
            cd.next_prot_id,
            cd.lyr_len,
            cd.proto_bits,
            cd.ip6_extension_count,
            cd.ip6_csum_proto as u32
        ));
    }
    {
        // arm 2: p[1]=1 -> lyr = 8+(1<<3) = 16 > len 8 -> TRUNCATED
        // AGAIN + false. vectors:14-:15.
        p[1] = 1;
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::HOPOPTS);
        let a2 = h.decode(&raw, &mut cd, &mut sink);
        push(format!("HOP lyr>len -> {}", a2 as i32));
    }
    {
        // probe_dec.cc:26 PIDS. vectors:16 `HOPPID 0 n=1`.
        let mut pv = Vec::new();
        h.get_protocol_ids(&mut pv);
        push(format!("HOPPID {} n={}", pv[0], pv.len()));
    }
    {
        // probe_dec.cc:27-:28 the dstopts PIDS-only arm (its decode
        // is probe-silent — literal transcription, cited unit arms
        // below). vectors:17 `DSTPID 60 n=1`.
        let dd = dstc::Ipv6DSTOptsCodec::new();
        let mut dv = Vec::new();
        dd.get_protocol_ids(&mut dv);
        push(format!("DSTPID {} n={}", dv[0], dv.len()));
    }
    {
        // probe_dec.cc:29-:36 routing arm on buffer q: q[0]=0x2b (43
        // ROUTING), q[2]=0 (type 0): EV 461 (ROUTE_ZERO, "evil
        // creatures" cc:95-:97) then EV 283 (TWO_ROUTE, cc:102-:103;
        // the 282 HOPOPTS arm stays silent). R6 var-first.
        // vectors:18-:20.
        let rr = routec::Ipv6RoutingCodec::new();
        let mut q = buf64();
        q[0] = 0x2b;
        q[2] = 0;
        let raw = fw::RawData { data: &q, len: 8 };
        let mut qc = fw::CodecData::new(None, fw::protocol_id::ROUTING);
        let b0 = rr.decode(&raw, &mut qc, &mut sink);
        push(format!(
            "ROUTE t0 -> {} next={} bits={}",
            b0 as i32,
            qc.next_prot_id,
            qc.proto_bits
        ));
        // probe_dec.cc:36. vectors:21 `ROUTE_PID 43 n=1`.
        let mut rv = Vec::new();
        rr.get_protocol_ids(&mut rv);
        push(format!("ROUTE_PID {} n={}", rv[0], rv.len()));
    }
    {
        // probe_dec.cc:37-:42 mobility arm on buffer m: m[0]=60
        // (!= NONEXT 59) -> EV 475 mid-write-run, decode STILL TRUE,
        // next=60 lands anyway. vectors:22-:23 + :24 PIDS.
        let mm = mobc::MobilityCodec::new();
        let mut m = buf64();
        m[0] = 60;
        let raw = fw::RawData { data: &m, len: 16 };
        let mut mc = fw::CodecData::new(None, fw::protocol_id::MOBILITY_IPV6);
        let c0b = mm.decode(&raw, &mut mc, &mut sink);
        push(format!("MOB badpayl -> {} next={}", c0b as i32, mc.next_prot_id));
        let mut mv = Vec::new();
        mm.get_protocol_ids(&mut mv);
        push(format!("MOB_PID {} n={}", mv[0], mv.len()));
    }
    {
        // probe_dec.cc:43-:49 the igmp faces: PIDS (vectors:25), the
        // record mod pair (vectors:26 `IGMP mod_ctor=1 mod_dtor=1` —
        // the ONLY 18e record with the Module pair), then the REAL
        // module: mod_ctor -> get_rules sid-walk (`while (rmap[n].sid)
        // n++`) + get_name -> vectors:27 `IGMP rules=1 sid0=455
        // name=igmp`. Rust face = the record presence bools +
        // IgmpModule + the landed rule_count walker (18d home).
        let ic = igmpc::IgmpCodec::new();
        let mut iv = Vec::new();
        ic.get_protocol_ids(&mut iv);
        push(format!("IGMP_PID {} n={}", iv[0], iv.len()));

        let ib = igmpc::CD_IGMP[0];
        push(format!(
            "IGMP mod_ctor={} mod_dtor={}",
            ib.mod_ctor as i32,
            ib.mod_dtor as i32
        ));
        let im = igmpc::IgmpModule::new(); // the mod_ctor() face (cc:95-:96)
        let n = snort3::codecs::codec_module::rule_count(igmpc::IgmpModule::get_rules());
        push(format!(
            "IGMP rules={} sid0={} name={}",
            n, igmpc::IGMP_RULES[0].sid,
            im.get_name()
        ));
        // ib->mod_dtor(im): the C deletes the module — the Rust
        // IgmpModule is stack-owned; the drop is the fold (row-18d
        // ownership posture, no observable).
    }

    for (i, (got, want_line)) in out.borrow().iter().zip(want.iter()).enumerate() {
        assert_eq!(got, want_line, "DEC transcript line {}", i + 1);
    }
    assert_eq!(out.borrow().len(), 27, "replay must emit exactly 27 lines");
}

// ==========================================================================
// 2. FACE-A load-face replay — vectors_faceA.txt 9 lines, ordered
//    (probe.cc table walk through the load_plugins witness; ext PLAN
//    §3: BOTH faces tracked pins). The witness body = stubs_18e.o
//    lineage (eth stubs face): load_plugins prints `LOAD <name>` per
//    table head over the FIVE REAL tables (retired-stub face — the
//    cd_hopopts stub is RETIRED, ext PLAN §4).
// ==========================================================================
#[test]
fn ext_face_a_load_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 9, "vectors_faceA.txt must hold the full 9-line load ladder");

    let mut out: Vec<String> = Vec::new();
    // probe.cc:14-:17 tabs[] = { cd_hopopts, cd_dstopts, cd_routing,
    // cd_mobility, cd_igmp } walked through the load_plugins witness —
    // the real-name LOAD face (ipv6_hop_opts NOT cd_hopopts_stub: the
    // FACE-A link carries zero codec_api object, ext PLAN §4d; the
    // stub names stay frozen ONLY in the vocab donor face).
    let tabs: [fw::CodecTable; 5] = [
        hopc::CD_HOP_OPTS,
        dstc::CD_DSTOPTS,
        routec::CD_ROUTING,
        mobc::CD_MOBILITY,
        igmpc::CD_IGMP,
    ];
    for t in tabs {
        for rec in t {
            out.push(format!("LOAD {}", rec.name));
        }
    }
    out.push("LOADS 5".to_string()); // probe.cc:17
    // probe.cc:18-:19 hopopts record face. vectors:7-8.
    let a = hopc::CD_HOP_OPTS[0];
    out.push(format!(
        "API hopopts type={} size={} ver={} name={}",
        a.ptype, a.size, a.api_version, a.name
    ));
    out.push(format!("HELP {}", a.help));
    // probe.cc:20 igmp record face (type/name/mod_ctor). vectors:9.
    let i = igmpc::CD_IGMP[0];
    out.push(format!(
        "API igmp type={} name={} mod_ctor={}",
        i.ptype,
        i.name,
        i.mod_ctor as i32
    ));

    for (line, (got, want_line)) in out.iter().zip(want.iter()).enumerate() {
        assert_eq!(got, want_line, "FACE-A transcript line {}", line + 1);
    }
    assert_eq!(out.len(), 9, "FACE-A replay must emit exactly 9 lines");
}

// ==========================================================================
// 3. Per-TU cited arms (every value derived from the C statements —
//    no vectors line claimed; the probe arms above pinned what the
//    probe pinned).
// ==========================================================================

/// cd_hop_opts 456 arm (cc:67-:71): DEAD on the probe default face
/// (ext recon §6.3, witness conf max_ip6_extensions = 0) — mutated
/// face measured here: conf.max_ip6_extensions = 2 &&
/// ip6_extension_count = 2 -> hit_ip6_maxopts TRUE (the landed
/// snort_config.h:450-:451 &&-face) -> EV 456 + false, and NO other
/// event (the ladder returns before any lyr/order work).
#[test]
fn hop_opts_excess_ext_arm_measured() {
    let mut conf = SnortConfig::default();
    conf.max_ip6_extensions = 2; // the vocab_parity cd_no_next mutated face, same posture
    let p = buf64();
    let raw = fw::RawData { data: &p, len: 8 };
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::HOPOPTS);
    cd.ip6_extension_count = 2;
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    let r = hopc::Ipv6HopOptsCodec::new().decode(&raw, &mut cd, &mut sink);
    assert!(!r); // cc:70 return false
    assert_eq!(evs, vec![(116, 456)]); // DECODE_IP6_EXCESS_EXT_HDR (codec_module.h:209, landed 18c)
    assert_eq!(cd.lyr_len, 0, "cc:70 returns before the cc:73 lyr write");
}

/// cd_dst_opts THE quirk (cc:63-:64, ext PLAN §3): the EXCESS arm has
/// NO return — with the SAME mutated-conf face as the hop arm above,
/// dstopts raises EV 456 and then KEEPS WALKING: EV 292 fires next
/// (nxt=ROUTING, cc:66-:67), the four writes run, decode returns TRUE.
/// The hopopts contrast (immediately above) is the pair half of the
/// never-unified rule.
#[test]
fn dst_opts_excess_without_return() {
    let mut conf = SnortConfig::default();
    conf.max_ip6_extensions = 2;
    let mut p = buf64();
    p[0] = 43; // ip6dest_nxt == ROUTING -> cc:66-:67 fires 292 AFTER 456
    let raw = fw::RawData { data: &p, len: 8 };
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::DSTOPTS);
    cd.ip6_extension_count = 2;
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    // R6 mirror (ext PLAN §3): the bool lands in a VAR before any
    // post-decode field read.
    let r = dstc::Ipv6DSTOptsCodec::new().decode(&raw, &mut cd, &mut sink);
    assert!(r, "cc:85-:87 continues past cc:63-:64 and true-returns via the PAD walk");
    assert_eq!(
        evs,
        vec![(116, 456), (116, 292)],
        "dstopts EXCESS-without-return: 292 must FOLLOW 456 (cc:63-:67 statement order)"
    );
    assert_eq!(cd.lyr_len, 8, "cc:69 ran (8 + (0<<3))");
    assert_eq!(cd.next_prot_id, 43); // cc:79
    assert_eq!(cd.proto_bits, fw::PROTO_BIT__IP6_EXT); // cc:77
}

/// cd_routing the 282 arm the probe did NOT fire (probe q[0]=43 hit
/// 461+283 only): nxt == HOPOPTS raises DECODE_IPV6_ROUTE_AND_
/// HOPBYHOP 282 (cc:99-:100) INSTEAD of 283 — the three event arms
/// are independent ifs, never an else-chain (literal kept). All-zero
/// routing header: type 0 also fires 461 first.
#[test]
fn routing_event_trio_independent_arms() {
    let q = buf64(); // q[0]=0=HOPOPTS, q[1]=0, q[2]=0 (type 0)
    let raw = fw::RawData {
        data: &q,
        len: 8,
    };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::ROUTING);
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    let r = routec::Ipv6RoutingCodec::new().decode(&raw, &mut cd, &mut sink);
    assert!(r); // cc:119
    assert_eq!(
        evs,
        vec![(116, 461), (116, 282)],
        "type0 461 then HOPOPTS-AND-ROUTE 282 (h:133); NO 283 — nxt(0) != ROUTING (h:134)"
    );
    assert_eq!(cd.next_prot_id, 0);
    // the third event face (283) is ALREADY vectors-pinned by the
    // DEC replay above — both half-faces of the trio now measured.
    // CODEC_ROUTING_SEEN lands via the landed check (codec.rs
    // :625-:626) — cited here, vectors-observable NONE:
    assert_ne!(cd.codec_flags & fw::CODEC_ROUTING_SEEN, 0);
}

/// the LADDER-ORDER discriminator (recon §6.4): hopopts checks
/// `raw.len < 8` BEFORE maxopts; mobility checks maxopts BEFORE any
/// len. Same mutated input (len 7, cnt 1, max 1 — BOTH conditions
/// true) answers with DIFFERENT events per TU: hop -> EV 272 only,
/// mob -> EV 456 only. If anyone ever "unifies" a ladder, this test
/// breaks first.
#[test]
fn ladder_order_never_unified() {
    let mut conf = SnortConfig::default();
    conf.max_ip6_extensions = 1;
    let p = buf64();
    let raw = fw::RawData { data: &p, len: 7 };

    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::HOPOPTS);
    cd.ip6_extension_count = 1;
    let mut hop_evs: Vec<(u32, u32)> = Vec::new();
    let mut hop_sink = |gid: u32, sid: u32| hop_evs.push((gid, sid));
    assert!(!hopc::Ipv6HopOptsCodec::new().decode(&raw, &mut cd, &mut hop_sink));
    assert_eq!(hop_evs, vec![(116, 272)], "hopopts cc:61 len guard runs FIRST — 456 unreachable");

    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::MOBILITY_IPV6);
    cd.ip6_extension_count = 1;
    let mut mob_evs: Vec<(u32, u32)> = Vec::new();
    let mut mob_sink = |gid: u32, sid: u32| mob_evs.push((gid, sid));
    assert!(!mobc::MobilityCodec::new().decode(&raw, &mut cd, &mut mob_sink));
    assert_eq!(mob_evs, vec![(116, 456)], "mobility cc:66 maxopts runs FIRST — 272 unreachable (len<8 would fire but the cc:69 return precedes the cc:72 guard)");

    // routing's THIRD shape (recon §6.4): MIN_EXT_LEN guard fires at
    // len 7 EVEN with the max arm live — the 456 arm stays unreachable
    // there too (cc:77 precedes cc:83; both-guard shape, neither
    // order shared with the two above).
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ROUTING);
    cd.ip6_extension_count = 1;
    let mut rt_evs: Vec<(u32, u32)> = Vec::new();
    let mut rt_sink = |gid: u32, sid: u32| rt_evs.push((gid, sid));
    assert!(!routec::Ipv6RoutingCodec::new().decode(&raw, &mut cd, &mut rt_sink));
    assert_eq!(rt_evs, vec![(116, 272)]);
}

/// cd_igmp decode arms via the LEFT-OPEN IpApiLite seam (module doc
/// of cd_igmp.rs; deviations row 18e names the seam — the PRODUCING
/// layer stays open, these arms only exercise the READ face):
///  A) cc:61-:72  is_ip4 && p[0]==0x11 && opt {0,0} len>=2 -> EV 455
///     + the ONLY false return.
///  B) opt_data None + !RTRALT && LEN_THREE -> EV 455 NO return ->
///     true (cc:77-:83).
///  C) both flags set -> silent true (the flag arm guard, cc:77).
///  D) is_ip4 false -> whole guard skipped silently, true (cc:61/:83).
#[test]
fn igmp_decode_arms_via_ipapi_lite() {
    let c = igmpc::IgmpCodec::new();

    // A) the DOS double-zero face
    static OPTS: [u8; 2] = [0, 0];
    let p = [0x11u8, 0, 0, 0];
    let raw = fw::RawData { data: &p, len: 4 };
    let snort = igmpc::IpApiLite {
        is_ip4: true,
        opt_data: Some(&OPTS),
        opt_len: 2,
    };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::IGMP);
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    assert!(!c.decode(&raw, &mut cd, &snort, &mut sink)); // cc:72
    assert_eq!(evs, vec![(116, 455)]); // DECODE_IGMP_OPTIONS_DOS, h:208 literal

    // B) flags face: opt_data nullptr (cc:65 arm skipped), LEN_THREE
    // set + RTRALT clear -> event, NO return.
    let snort = igmpc::IpApiLite {
        is_ip4: true,
        opt_data: None, // cc:63 nullptr -> the cc:65 if skips
        opt_len: 0,
    };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::IGMP);
    cd.codec_flags = fw::CODEC_IPOPT_LEN_THREE; // codec.h:45 posture, landed codec.rs:48
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    assert!(c.decode(&raw, &mut cd, &snort, &mut sink)); // cc:83 true
    assert_eq!(evs, vec![(116, 455)], "the flags arm fires the SAME sid WITHOUT returning (cc:77-:82)");

    // C) both flags -> the compound guard fails on the FIRST operand
    // (cc:77 `!(flags & RTRALT)`).
    let mut cd = fw::CodecData::new(None, fw::protocol_id::IGMP);
    cd.codec_flags = fw::CODEC_IPOPT_RTRALT_SEEN | fw::CODEC_IPOPT_LEN_THREE;
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    assert!(c.decode(&raw, &mut cd, &snort, &mut sink));
    assert!(evs.is_empty(), "cc:77 !RTRALT operand gates the event");

    // D) not-v4 -> whole guard silent (cc:61 first operand).
    let snort4 = igmpc::IpApiLite::default();
    let mut cd = fw::CodecData::new(None, fw::protocol_id::IGMP);
    let mut evs: Vec<(u32, u32)> = Vec::new();
    let mut sink = |gid: u32, sid: u32| evs.push((gid, sid));
    // p[0]==0x11 stays true — is_ip4 alone gates (raw.len>=1 operand
    // already proven by arm A/B).
    assert!(c.decode(&raw, &mut cd, &snort4, &mut sink));
    assert!(evs.is_empty());
}

/// cd_igmp the Module/rules face (vectors:27 lines' C-side identity):
/// the ONE-row igmp_rules + terminator (msg slot never read past the
/// sid-0 stop — 18d RuleMap posture), the module name/gid, and the
/// msg LITERAL.
#[test]
fn igmp_module_rules_census() {
    assert_eq!(
        snort3::codecs::codec_module::rule_count(igmpc::IgmpModule::get_rules()),
        1,
        "cc:34-:37: one live row + the {{ 0, nullptr }} terminator"
    );
    assert_eq!(igmpc::IGMP_RULES[0].sid, 455); // codec_module.h:208 DECODE_IGMP_OPTIONS_DOS
    assert_eq!(
        igmpc::IGMP_RULES[0].msg,
        Some("DOS IGMP IP options validation attempt")
    ); // cc:36 verbatim
    assert_eq!(igmpc::IGMP_RULES[1].sid, 0);
    assert_eq!(igmpc::IGMP_RULES[1].msg, None, "terminator msg slot never read");
    let m = igmpc::IgmpModule::new();
    assert_eq!(m.get_name(), "igmp"); // vectors:27 name face
    assert_eq!(m.base.get_gid(), 116); // h:249-:250 via BaseCodecModule (vectors-silent cite)
    assert_eq!(m.base.get_usage(), 1); // h:253-:254 CONTEXT (module.h:216 order), cite-only face
    assert!(!m.base.is_list); // h:246-:247 default posture, 2-arg ctor
}

/// record census across the five 18e records (vectors:1/:3/:5/:7/:9
/// faces incl. the FACE-A igmp line): shared const identity + the
/// mod-pair CENSUS — igmp alone carries mod_ctor/mod_dtor TRUE (its
/// cc:118-:119 SET pair; the other four nullptr). Names + HELPs verbatim
/// incl. the case asymmetry (hopopts "IPv6" vs dstopts "ipv6" — the
/// literals NEVER normalized).
#[test]
fn ext_record_census() {
    let recs = [
        hopc::CD_HOP_OPTS[0],
        dstc::CD_DSTOPTS[0],
        routec::CD_ROUTING[0],
        mobc::CD_MOBILITY[0],
        igmpc::CD_IGMP[0],
    ];
    for r in recs {
        assert_eq!(r.ptype, fw::PT_CODEC); // vectors `type=0`
        assert_eq!(r.size, 112); // CDAPI_SIZEOF pin (vectors `size=112`)
        assert_eq!(r.api_version, 1900547); // (29<<16)|3 (vectors `ver=1900547`)
        assert_eq!(r.features, fw::PLUGIN_SO_RELOAD); // features=1 face x5 (no 18c features=0 outlier here)
        assert!(r.ctor && r.dtor);
        assert!(!(r.pinit || r.pterm || r.tinit || r.tterm));
    }
    let names: Vec<&str> = recs.iter().map(|r| r.name).collect();
    assert_eq!(
        names,
        vec![
            "ipv6_hop_opts",
            "ipv6_dst_opts",
            "ipv6_routing",
            "ipv6_mobility",
            "igmp"
        ]
    ); // FACE-A LOAD lines (vectors_faceA:1-:5) — the load order == tabs[] order
    assert_eq!(
        recs[0].help,
        "support for IPv6 hop options"
    ); // capital-I face
    assert_eq!(
        recs[1].help,
        "support for ipv6 destination options"
    ); // lowercase face — asymmetry kept
    let mods: Vec<(bool, bool)> = recs.iter().map(|r| (r.mod_ctor, r.mod_dtor)).collect();
    assert_eq!(
        mods,
        vec![
            (false, false),
            (false, false),
            (false, false),
            (false, false),
            (true, true)
        ],
        "igmp is the ONLY 18e record with the Module pair (cc:39-:47 + cc:118-:119; vectors_faceA:9 + vectors:26)"
    );
}

/// the codec_api.rs tripwire census (ext PLAN §6: "real records land
/// per row TU, NEVER rename/fork the stub consts"): the four 18e-only
/// names were ALREADY in the 34-name STATIC ladder (cc-order indexes
/// pinned at codec_api.rs:102/:116/:118/:125 as grep-verified in the
/// recon), and cd_hopopts is NOT in that ladder — it rides the
/// always-loaded five (codec_api.cc:34 extern + :82 load_plugins, the
/// E6 landmine face ext PLAN §4). STATIC_CODECS stays false: 18e's
/// real Rust records flip NOTHING dormant (the frozen vocab stub face
/// stays pinned by 18c's vocab_parity test, untouched).
#[test]
fn ext_static_names_tripwire() {
    let names = capi::STATIC_CODEC_EXTERN_NAMES;
    assert_eq!(names.len(), 34);
    assert_eq!(names[4], "cd_dstopts"); // codec_api.rs:102
    assert_eq!(names[18], "cd_igmp"); // codec_api.rs:116
    assert_eq!(names[20], "cd_mobility"); // codec_api.rs:118
    assert_eq!(names[27], "cd_routing"); // codec_api.rs:125
    assert!(
        !names.contains(&"cd_hopopts"),
        "cd_hopopts rides the always-loaded five (codec_api.cc:34/:82) — NEVER a STATIC ladder name; the frozen cd_hopopts_stub twin lives at codec_api.rs:85 (18c face, untouched this row)"
    );
    // the dormant face read-back (vocab_parity_test.rs:254 block-form
    // precedent: assertions_on_constants intentional — the pinned
    // false is the drift tripwire a later row must trip).
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(!capi::STATIC_CODECS, "the 18e real records flip nothing at the dormant ladder");
    }
}
