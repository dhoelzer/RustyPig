//! Parity test for the row-18h SMALL FOUR ports — four ground TUs
//! (ip/cd_esp.cc 227 L d9a20eae / ip/cd_frag.cc 190 L 2832f4fd /
//! ip/cd_pgm.cc 211 L 6b476f5c / ip/cd_auth.cc 172 L e9ce9351; wc+md5
//! re-measured and asserted EVERY build by tools/small4_harness/
//! build.sh :36-:41). ZERO-gate row (small4 PLAN §4): the four TUs ship
//! NO embedded suite (combined grep TEST_CASE|TEST_GROUP|^TEST(|UNIT_TEST
//! == 0 x4, re-asserted every build) — so this suite carries NO
//! up_gate_* set: honest absence, census-cited (the 18d/18e/18f
//! zero-suite precedent, recorded in deviations row 18h).
//!
//! Ground truth #1: `tools/small4_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 46 L NEVER edited, md5
//! 462f0ff6ed44220564c5ef0c8538ad80 (the -O0 == -O2 byte-ident pair
//! cmp-armed every build). WHOLE transcript replays HERE line-for-line
//! as ONE ordered session (per-index assert_eq over want.len()==46).
//! THE FRAG INTERLEAVE IS THE ORDER FACE: four events + three flags
//! across ONE decode — the 459 head does NOT return (cc:70 commented
//! `return false` DEAD), so `EV 116 459` then `EV 116 458` ride AHEAD
//! of `FRAG zero8 -> 1 ... dflags=0` EXACTLY in ground call order,
//! NEVER sorted (small4 PLAN §8). The order-EV-rides-a-SUCCESS arms
//! (vectors:8/:9 `EV 116 296` + `ESP order66 -> 1 flags=1030`;
//! vectors:22/:23; vectors:43/:44) pin the codec_flags OOO latch
//! decomposition 6|0x400 = 1030 (python-pinned BOTH ends in build.sh).
//!
//! Ground truth #2: `tools/small4_harness/vectors_faceA.txt` — the
//! FACE-A load/walk face (probe.cc, ONE probe x FOUR tables through the
//! in-probe load_plugins witness), 17 L, md5
//! 4755d48c54cc057b3c3c9eafec01c7cf. THE DRIFT LIVES IN THIS
//! TRANSCRIPT: `LOAD ipv6_frag` (frag NAME != file base) and
//! `LOAD auth` + `API ah ... name=auth` while the C table is cd_ah —
//! the link-symbol-vs-printed-NAME face replayed verbatim from the
//! Rust records. mod_ctor asymmetry 1/0/1/1 (frag api :170-:171
//! nullptr arm — the R2 pin) is part of the transcript, arm BOTH faces.
//!
//! Eval-order: EV lines land between the decode call and the summary
//! printf exactly as the C sink prints them (`EV %u %u` via GID_DECODE
//! 116, the landed framework codec_event — the eth/ext/tun/gre
//! lineage). The R6 var-first posture is mirrored: every decode bool
//! is stored BEFORE the post-decode field reads (build.sh :grep-asserts
//! the C face: `bool x=...->decode` >= 12, printf.*->decode == 0).
//!
//! Config-gate seams replayed: esp `decode_esp` bool re-armed per arm
//! exactly where probe_dec.cc writes conf.enable_esp (gate-off false
//! first, then true); max_ip6_extensions mutations re-armed per arm
//! (maxopts arms set 1/count 1, ORDER arms set max=5 +
//! curr_ip6_extension, reset to 0 after — the probe's conf reuse face).

use snort3::codecs::cd_auth as ah;
use snort3::codecs::cd_esp as esp;
use snort3::codecs::cd_frag as frag;
use snort3::codecs::cd_pgm as pgm;
use snort3::codecs::codec_api as capi;
use snort3::codecs::codec_module as cm;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/small4_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/small4_harness/vectors_faceA.txt");

/// probe_dec.cc zeroed buffers (`uint8_t z[96]={0}`, e[32], f[16],
/// p[48], a[24], b6[40]) — separate arrays, mutation per arm below.
fn buf96() -> [u8; 96] {
    [0u8; 96]
}
fn buf32() -> [u8; 32] {
    [0u8; 32]
}
fn buf16() -> [u8; 16] {
    [0u8; 16]
}
fn buf48() -> [u8; 48] {
    [0u8; 48]
}
fn buf24() -> [u8; 24] {
    [0u8; 24]
}
fn buf40() -> [u8; 40] {
    [0u8; 40]
}

/// probe_dec.cc:21-:22 set_ip6: b6 zeroed, b6[0]=0x60 -> the d.ip_api
/// face lands as the row seams' is_ip6=true (the producing IpApi layer
/// stays open; 0x60 version nibble is the C discriminator, the seam
/// carries the boolean read face).
fn ip6_on() -> bool {
    true
}
#[allow(dead_code)]
fn _set_ip6_marker(b: &mut [u8; 40]) {
    b[0] = 0x60;
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 46 lines, ordered,
//    one session (probe_dec.cc statement order, R6 var-first mirrored).
// ==========================================================================
#[test]
fn small4_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 46, "vectors.txt must hold the full 46-line DEC ladder");

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

    // probe_dec.cc:25 one shared conf across arms (NSDMI
    // enable_esp=false + max_ip6_extensions=0 faces); the config gate
    // re-arms per arm exactly where the probe writes conf.enable_esp.
    let mut conf = SnortConfig::default();
    let mut decode_esp = false; // SnortConfig::esp_decoding() seam (left-open)

    // ---- ESP (probe_dec.cc:26 ea=cd_esp[0]; :32-:66) ----
    let ec = esp::EspCodec::new(); // ea->ctor(nullptr)

    // vectors:1 gate-off (conf default false; no EV, no mutation)
    {
        let z = buf96();
        let raw = fw::RawData { data: &z, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
        let mut dd = esp::EspDecodeData::default();
        let b = ec.decode(&raw, &mut cd, &mut dd, decode_esp, &mut sink);
        push(format!("ESP gate-off -> {}", b as u8));
    }
    decode_esp = true; // conf.enable_esp = true (probe :37)

    // vectors:2/:3 short21 -> EV 294 + false (cc:105-:109)
    {
        let z = buf96();
        let raw = fw::RawData { data: &z, len: 21 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
        let mut dd = esp::EspDecodeData::default();
        let b = ec.decode(&raw, &mut cd, &mut dd, decode_esp, &mut sink);
        push(format!("ESP short21 -> {}", b as u8));
    }
    // vectors:4 ok24: e[10]=0 pad, e[11]=6 next -> lyr 8 next 6 flags 6
    {
        let mut e = buf32();
        e[10] = 0;
        e[11] = 6;
        let raw = fw::RawData { data: &e, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
        let mut dd = esp::EspDecodeData::default();
        let b = ec.decode(&raw, &mut cd, &mut dd, decode_esp, &mut sink);
        push(format!(
            "ESP ok24 -> {} lyr={} next={} flags={}",
            b as u8, cd.lyr_len, cd.next_prot_id, cd.codec_flags
        ));
    }
    // vectors:5 pad255 -> cc:150-:155 TRUST face (dflags rides the seam)
    {
        let mut e = buf32();
        e[10] = 255;
        e[11] = 6;
        let raw = fw::RawData { data: &e, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
        let mut dd = esp::EspDecodeData::default();
        let b = ec.decode(&raw, &mut cd, &mut dd, decode_esp, &mut sink);
        push(format!(
            "ESP pad255 -> {} next={} dflags={}",
            b as u8, cd.next_prot_id, dd.decode_flags
        ));
    }
    // vectors:6/:7 maxopts EV 456 (cc:129-:133; max=1 count=1); reset
    {
        let mut e = buf32();
        e[10] = 0;
        e[11] = 6;
        let b6 = buf40();
        conf.max_ip6_extensions = 1;
        let raw = fw::RawData { data: &e, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
        cd.ip6_extension_count = 1;
        let mut dd = esp::EspDecodeData { is_ip6: ip6_on(), decode_flags: 0 };
        let _b6 = &b6; // probe's set_ip6 buffer — the seam carries bool
        let b = ec.decode(&raw, &mut cd, &mut dd, decode_esp, &mut sink);
        push(format!("ESP maxopts -> {}", b as u8));
        conf.max_ip6_extensions = 0;
    }
    // vectors:8/:9 ORDER rides a SUCCESS: ESP order 6 <= curr 6 -> EV
    // 296 + OOO latch; final flags = ENCAP 6 | IP6_EXT_OOO 0x400 = 1030
    {
        let mut e = buf32();
        e[10] = 0;
        e[11] = 6;
        let b6 = buf40();
        conf.max_ip6_extensions = 5;
        let raw = fw::RawData { data: &e, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
        cd.curr_ip6_extension = 6;
        let mut dd = esp::EspDecodeData { is_ip6: ip6_on(), decode_flags: 0 };
        let _b6 = &b6;
        let b = ec.decode(&raw, &mut cd, &mut dd, decode_esp, &mut sink);
        push(format!("ESP order66 -> {} flags={}", b as u8, cd.codec_flags));
        conf.max_ip6_extensions = 0;
    }
    // vectors:10 ESPPID (cc:84-:85)
    {
        let mut v = Vec::new();
        ec.get_protocol_ids(&mut v);
        push(format!(
            "ESPPID {} n={}",
            v.first().copied().unwrap_or(0),
            v.len()
        ));
    }
    // vectors:11 ESPRULES table walk + module NAME (cc:36-:40/:50-:56)
    {
        let m = esp::EspModule::new();
        let rm = esp::EspModule::get_rules();
        let n = cm::rule_count(rm);
        push(format!(
            "ESPRULES {} sid0={} name={}",
            n,
            rm[0].sid,
            m.base.name
        ));
    }

    // ---- FRAG (probe_dec.cc:71 fc=fa->ctor; NO module face — R2) ----
    let fc = frag::Ipv6FragCodec::new();

    // vectors:12/:13 short7 -> EV 272 + false (cc:52-:56, MIN_EXT_LEN 8)
    {
        let z = buf96();
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::FRAGMENT);
        let mut fd = frag::FragDecodeData::default();
        let b = fc.decode(&raw, &mut cd, &mut fd, &mut sink);
        push(format!("FRAG short7 -> {}", b as u8));
    }
    // vectors:14/:15 maxopts EV 456 after the len guard (cc:58-:62)
    {
        let f = buf16();
        conf.max_ip6_extensions = 1;
        let raw = fw::RawData { data: &f, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::FRAGMENT);
        cd.ip6_extension_count = 1;
        let mut fd = frag::FragDecodeData::default();
        let b = fc.decode(&raw, &mut cd, &mut fd, &mut sink);
        push(format!("FRAG maxopts -> {}", b as u8));
        conf.max_ip6_extensions = 0;
    }
    // vectors:16-:18 THE INTERLEAVE HEAD: len==8 -> EV 459 (NO return,
    // cc:70 dead), off 0/MF 0 -> EV 458 (cc:91), THEN order x2 (cc:102
    // FRAGMENT curr->4; cc:111 nxt UDP 17 -> MAX > 4 -> curr->7, NO
    // 296), dflags stays 0, next = 17 (cc:124). NEVER sorted.
    {
        let mut f = buf16();
        f[0] = 17;
        let raw = fw::RawData { data: &f, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::FRAGMENT);
        let mut fd = frag::FragDecodeData::default();
        let b = fc.decode(&raw, &mut cd, &mut fd, &mut sink);
        push(format!(
            "FRAG zero8 -> {} lyr={} next={} dflags={}",
            b as u8, cd.lyr_len, cd.next_prot_id, fd.decode_flags
        ));
    }
    // vectors:19 MF arm: offlg BE bytes 2-3 = 0x0001 -> DECODE_MF 128 +
    // DECODE_FRAG 64 = 192; no 458; next = FINISHED_DECODE 256
    {
        let mut f = buf16();
        f[0] = 6;
        f[2] = 0x00;
        f[3] = 0x01;
        let raw = fw::RawData { data: &f, len: 16 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::FRAGMENT);
        let mut fd = frag::FragDecodeData::default();
        let b = fc.decode(&raw, &mut cd, &mut fd, &mut sink);
        push(format!(
            "FRAG mf -> {} next={} dflags={}",
            b as u8, cd.next_prot_id, fd.decode_flags
        ));
    }
    // vectors:20-:23 ooo2: 459 + 458 then SECOND order call HOPOPTS:
    // order 1 <= curr 4 -> EV 296 (next_order here = FRAGMENT's 4 at
    // cc:111 — next_prot_id still FRAGMENT, the cc:98 FIXIT-RC face);
    // DECODE_FRAG unset -> next = ip6f_nxt = 0
    {
        let mut f = buf16();
        f[0] = 0;
        let raw = fw::RawData { data: &f, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::FRAGMENT);
        let mut fd = frag::FragDecodeData::default();
        let b = fc.decode(&raw, &mut cd, &mut fd, &mut sink);
        push(format!("FRAG ooo2 -> {} next={}", b as u8, cd.next_prot_id));
    }
    // vectors:24 off8: offlg 0x0008 -> DECODE_FRAG only, FINISHED 256
    {
        let mut f = buf16();
        f[0] = 6;
        f[3] = 0x08;
        let raw = fw::RawData { data: &f, len: 16 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::FRAGMENT);
        let mut fd = frag::FragDecodeData::default();
        let b = fc.decode(&raw, &mut cd, &mut fd, &mut sink);
        push(format!(
            "FRAG off8 -> {} next={} dflags={}",
            b as u8, cd.next_prot_id, fd.decode_flags
        ));
    }
    // vectors:25 FRAGPID (cc:130-:131)
    {
        let mut v = Vec::new();
        fc.get_protocol_ids(&mut v);
        push(format!(
            "FRAGPID {} n={}",
            v.first().copied().unwrap_or(0),
            v.len()
        ));
    }
    // vectors:26 THE R2 FACE: frag api mod pair nullptr (cc:170-:171)
    {
        let r = frag::IPV6_FRAG_API;
        push(format!(
            "FRAG api mod_ctor={} mod_dtor={}",
            r.mod_ctor as u8, r.mod_dtor as u8
        ));
    }

    // ---- PGM (probe_dec.cc:105 pc; decode ALWAYS true) ----
    let pc = pgm::PgmCodec::new();

    // vectors:27-:29 ERR arms (len 44, odd 45, type != 8): NO EV
    {
        let z = buf96();
        let raw = fw::RawData { data: &z, len: 44 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::PGM);
        let b = pc.decode(&raw, &mut cd, &mut sink);
        push(format!("PGM len44 -> {}", b as u8));
    }
    {
        let z = buf96();
        let raw = fw::RawData { data: &z, len: 45 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::PGM);
        let b = pc.decode(&raw, &mut cd, &mut sink);
        push(format!("PGM len45 -> {}", b as u8));
    }
    {
        let mut p = buf48();
        p[4] = 9; // type != 8 -> cc:120 ERR
        let raw = fw::RawData { data: &p, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::PGM);
        let b = pc.decode(&raw, &mut cd, &mut sink);
        push(format!("PGM type9 -> {}", b as u8));
    }
    // vectors:30/:31 VULN: data_left 12 > opt.len 8, checksum 0 SKIPS
    // the cksum (cc:135) -> EV 454 — the ONLY pgm event site (cc:156)
    {
        let mut p = buf48();
        p[4] = 8;
        p[36] = 2;
        p[37] = 8;
        let raw = fw::RawData { data: &p, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::PGM);
        let b = pc.decode(&raw, &mut cd, &mut sink);
        push(format!("PGM nak-vuln -> {}", b as u8));
    }
    // vectors:32 cksum-guard: checksum 0xFFFF nonzero -> cksum_add over
    // the 48-byte window folds NONZERO -> ERR, NO EV (cc:139-:140; the
    // landed 18b cksum_add replays the C fold byte-exact — the 18g
    // two-way parity face extended, pgm rider)
    {
        let mut p = buf48();
        p[4] = 8;
        p[6] = 0xFF;
        p[7] = 0xFF;
        p[0] = 0x01;
        p[36] = 2;
        p[37] = 8;
        let raw = fw::RawData { data: &p, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::PGM);
        let b = pc.decode(&raw, &mut cd, &mut sink);
        push(format!("PGM cksum-guard -> {}", b as u8));
    }
    // vectors:33 optlen-ok: data_left 12 <= opt.len 200 -> OK, no EV
    {
        let mut p = buf48();
        p[4] = 8;
        p[36] = 2;
        p[37] = 200;
        let raw = fw::RawData { data: &p, len: 48 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::PGM);
        let b = pc.decode(&raw, &mut cd, &mut sink);
        push(format!("PGM optlen-ok -> {}", b as u8));
    }
    // vectors:34 PGMPID (cc:160-:163)
    {
        let mut v = Vec::new();
        pc.get_protocol_ids(&mut v);
        push(format!(
            "PGMPID {} n={}",
            v.first().copied().unwrap_or(0),
            v.len()
        ));
    }
    // vectors:35 PGMRULES (cc:37-:41; module NAME "pgm")
    {
        let m = pgm::PgmModule::new();
        let rm = pgm::PgmModule::get_rules();
        let n = cm::rule_count(rm);
        push(format!(
            "PGMRULES {} sid0={} name={}",
            n,
            rm[0].sid,
            m.base.name
        ));
    }

    // ---- AUTH (probe_dec.cc:133 aa=cd_ah[0]; the drift ride) ----
    let ac = ah::AuthCodec::new();

    // vectors:36/:37 short15 -> EV 465 + false (cc:90-:94, 16-byte min)
    {
        let z = buf96();
        let raw = fw::RawData { data: &z, len: 15 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::AUTH);
        let dd = ah::AuthDecodeData::default();
        let b = ac.decode(&raw, &mut cd, &dd, &mut sink);
        push(format!("AH short15 -> {}", b as u8));
    }
    // vectors:38/:39 badlen: a[1]=8 -> lyr 8+32=40 > 16 -> EV 466 + false
    {
        let mut a = buf16();
        a[1] = 8;
        let raw = fw::RawData { data: &a, len: 16 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::AUTH);
        let dd = ah::AuthDecodeData::default();
        let b = ac.decode(&raw, &mut cd, &dd, &mut sink);
        push(format!("AH badlen -> {}", b as u8));
    }
    // vectors:40 ok24 ip4 face: lyr 8+16=24, next = a[0] = 6; the ip6
    // block SKIPPED (cc:109 guard — contrast frag's unconditional body)
    {
        let mut a = buf24();
        a[0] = 6;
        a[1] = 4;
        let raw = fw::RawData { data: &a, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::AUTH);
        let dd = ah::AuthDecodeData::default();
        let b = ac.decode(&raw, &mut cd, &dd, &mut sink);
        push(format!("AH ok24 -> {} lyr={} next={}", b as u8, cd.lyr_len, cd.next_prot_id));
    }
    // vectors:41/:42 maxopts EV 456 (cc:111-:115)
    {
        let mut a = buf24();
        a[0] = 6;
        a[1] = 4;
        let b6 = buf40();
        conf.max_ip6_extensions = 1;
        let raw = fw::RawData { data: &a, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::AUTH);
        cd.ip6_extension_count = 1;
        let dd = ah::AuthDecodeData { is_ip6: ip6_on() };
        let _b6 = &b6;
        let b = ac.decode(&raw, &mut cd, &dd, &mut sink);
        push(format!("AH maxopts -> {}", b as u8));
        conf.max_ip6_extensions = 0;
    }
    // vectors:43/:44 order55 rides a SUCCESS (cc:117 AUTH 5 <= curr 5
    // -> EV 296; decode still true, next=6)
    {
        let mut a = buf24();
        a[0] = 6;
        a[1] = 4;
        let b6 = buf40();
        conf.max_ip6_extensions = 5;
        let raw = fw::RawData { data: &a, len: 24 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::AUTH);
        cd.curr_ip6_extension = 5;
        let dd = ah::AuthDecodeData { is_ip6: ip6_on() };
        let _b6 = &b6;
        let b = ac.decode(&raw, &mut cd, &dd, &mut sink);
        push(format!("AH order55 -> {} next={}", b as u8, cd.next_prot_id));
        conf.max_ip6_extensions = 0;
    }
    // vectors:45 AHPID (cc:83-:84)
    {
        let mut v = Vec::new();
        ac.get_protocol_ids(&mut v);
        push(format!(
            "AHPID {} n={}",
            v.first().copied().unwrap_or(0),
            v.len()
        ));
    }
    // vectors:46 AHRULES 2 sid0=465 name=auth (cc:35-:40; NAME "auth")
    {
        let m = ah::AuthModule::new();
        let rm = ah::AuthModule::get_rules();
        let n = cm::rule_count(rm);
        push(format!(
            "AHRULES {} sid0={} name={}",
            n,
            rm[0].sid,
            m.get_name()
        ));
    }

    let got = out.borrow();
    assert_eq!(got.len(), 46, "replay produced {} lines, expected 46", got.len());
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 2. FACE-A whole-transcript replay — vectors_faceA.txt 17 lines,
//    ordered (probe.cc: in-probe load_plugins x4 + LOADS 4 + per-table
//    API/HELP/mod_ctor walk). THE DRIFT FACE RIDES THE TRANSCRIPT.
// ==========================================================================
#[test]
fn small4_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 17, "vectors_faceA.txt must hold the full 17-line walk");

    let mut got: Vec<String> = Vec::new();

    // the witness load face: for (; p && *p; ++p) printf("LOAD %s", (*p)->name)
    for tab in [esp::CD_ESP, frag::CD_FRAG, pgm::CD_PGM, ah::CD_AH] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
    }
    got.push("LOADS 4".to_string());

    // probe.cc:18-:19 nm[4] = { "esp", "frag", "pgm", "ah" } — the
    // "ah" tag is the probe's table shorthand; the NAME slot prints
    // "auth" (the drift, module doc of cd_auth.rs).
    let tabs = [esp::CD_ESP, frag::CD_FRAG, pgm::CD_PGM, ah::CD_AH];
    let nm = ["esp", "frag", "pgm", "ah"];
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

    assert_eq!(got.len(), 17);
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "faceA line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 3. THE NAME-DRIFT TRIPWIRE (the row's headline, small4 PLAN §3/R1).
//    File-base-vs-extern PAIRS pinned: cd_auth.cc <-> ladder "cd_ah"
//    (the cd_hop_opts 18e family precedent, codified 18g).
// ==========================================================================
#[test]
fn small4_static_names_tripwire() {
    let names = capi::STATIC_CODEC_EXTERN_NAMES;
    assert_eq!(names.len(), 34);
    // the four ladder entries, cc-order positions (codec_api.rs sed
    // pins: cd_ah :98 / cd_esp :105 / cd_frag :108 / cd_pgm :121)
    assert_eq!(names[0], "cd_ah"); // codec_api.rs:98 — the DRIFT entry
    assert_eq!(names[7], "cd_esp"); // codec_api.rs:105
    assert_eq!(names[10], "cd_frag"); // codec_api.rs:108
    assert_eq!(names[23], "cd_pgm"); // codec_api.rs:121
    // THE headline assertion: NO ladder entry named cd_auth exists --
    // ground greps the TABLE name cd_ah (build.sh keeps the whole-src
    // 'extern ... cd_auth' grep DEAD-EMPTY every build).
    assert!(
        !names.contains(&"cd_auth"),
        "an extern/ladder entry named cd_auth would flip the 18g name-drift correction (ground has ONLY cd_ah: codec_api.cc:40, table cd_auth.cc:166)"
    );
    // the file-vs-table PAIR face: the Rust file base stays TRUE
    // (cd_auth.rs) while its table constant mirrors the C table name.
    assert_eq!(ah::CD_AUTH_NAME, "auth"); // cc:30 printed NAME
    assert_eq!(ah::CD_AH[0].name, "auth"); // record NAME slot (API line)
    assert_eq!(ah::AH_API.name, ah::CD_AUTH_NAME); // ah_api cc:141 <-> "auth" cc:150
    // frag rider: file==table but api/name diverge (cc:159 / cc:31)
    assert_eq!(frag::CD_IPV6_FRAG_NAME, "ipv6_frag");
    assert_eq!(frag::IPV6_FRAG_API.name, "ipv6_frag");
    // esp/pgm TRUE names hold (file base == table == ladder == NAME)
    assert_eq!(esp::CD_ESP[0].name, "esp");
    assert_eq!(pgm::CD_PGM[0].name, "pgm");
    // the dormant face read-back (vocab_parity precedent; pinned false)
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(!capi::STATIC_CODECS, "the 18h real records flip nothing at the dormant ladder");
    }
}

// ==========================================================================
// 4. Record census — all four CodecApi records: CDAPI carry 112/
//    1900547/1900547 + the mod_ctor asymmetry census 1/0/1/1 (the R2
//    frag nullptr pair, cc:170-:171; the 18f teredo precedent pinned).
// ==========================================================================
#[test]
fn small4_record_census() {
    let recs: [(&fw::CodecApiRecord, bool); 4] = [
        (esp::CD_ESP[0], true),
        (frag::CD_FRAG[0], false),
        (pgm::CD_PGM[0], true),
        (ah::CD_AH[0], true),
    ];
    for (r, mod_live) in recs {
        assert_eq!(r.ptype, fw::PT_CODEC);
        assert_eq!(r.size, fw::CDAPI_SIZEOF_CODEC_API); // 112 probe pin
        assert_eq!(r.api_version, fw::CDAPI_VERSION); // 1900547
        assert_eq!(r.version, 0);
        assert_eq!(r.features, fw::PLUGIN_SO_RELOAD);
        assert_eq!(r.options, fw::API_OPTIONS);
        assert_eq!(r.mod_ctor, mod_live);
        assert_eq!(r.mod_dtor, mod_live);
        assert!(!r.pinit && !r.pterm && !r.tinit && !r.tterm); // 112-face nullptrs
        assert!(r.ctor && r.dtor); // all four ctor/dtor SET
    }
    // tables: exactly one record each (the nullptr terminator rides
    // the slice length, 18c fold deviation)
    assert_eq!(esp::CD_ESP.len(), 1);
    assert_eq!(frag::CD_FRAG.len(), 1);
    assert_eq!(pgm::CD_PGM.len(), 1);
    assert_eq!(ah::CD_AH.len(), 1);
}

// ==========================================================================
// 5. RuleMap census — ground table shapes VERBATIM (1/0/1/2 entries +
//    terminators; the { DECODE_ grep census is ground-side in build.sh)
//    and the messages byte-exact against cc.
// ==========================================================================
#[test]
fn small4_rules_census() {
    assert_eq!(cm::rule_count(&esp::ESP_RULES), 1);
    assert_eq!(esp::ESP_RULES[0].sid, 294);
    assert_eq!(
        esp::ESP_RULES[0].msg,
        Some("truncated encapsulated security payload header")
    ); // cc:38
    assert_eq!(esp::ESP_RULES[1].sid, 0);

    assert_eq!(cm::rule_count(&pgm::PGM_RULES), 1);
    assert_eq!(pgm::PGM_RULES[0].sid, 454);
    assert_eq!(pgm::PGM_RULES[0].msg, Some("PGM nak list overflow attempt")); // cc:39

    assert_eq!(cm::rule_count(&ah::AUTH_RULES), 2); // vectors:46 AHRULES 2
    assert_eq!(ah::AUTH_RULES[0].sid, 465);
    assert_eq!(ah::AUTH_RULES[0].msg, Some("truncated authentication header")); // cc:37
    assert_eq!(ah::AUTH_RULES[1].sid, 466);
    assert_eq!(ah::AUTH_RULES[1].msg, Some("bad authentication header length")); // cc:38

    // THE R2 ABSENCE FACE: frag carries NO RuleMap/NO Parameter at all
    // (ground grep 0; a params table anywhere in cd_frag.rs would drift
    // FROM ground — the compile-time absence is itself the pin; the
    // mod_ctor=0 transcript arm lives in the DEC replay above. There is
    // no frag::FRAG_RULES symbol to census — asserting its absence at
    // runtime is impossible; the vectors arms pin the face.)
}

// ==========================================================================
// 6. pgm_nak_detect tri-state units (the file-scope statics face R3:
//    the internals are NOT exported in C — the Rust arms land as the
//    same tri-state; cited to cc, NO vectors pre-typed anywhere).
// ==========================================================================
#[test]
fn small4_pgm_nak_tri_state() {
    let z = buf96();
    // cc:112 len <= 44 OR odd -> ERR: the 44, 45(odd) arms
    let r44 = fw::RawData { data: &z, len: 44 };
    assert_eq!(pgm::pgm_nak_detect(&r44), pgm::PGM_NAK_ERR);
    let r45 = fw::RawData { data: &z, len: 45 };
    assert_eq!(pgm::pgm_nak_detect(&r45), pgm::PGM_NAK_ERR);
    // cc:120 type != 8
    let mut p = buf48();
    p[4] = 9;
    let rp = fw::RawData { data: &p, len: 48 };
    assert_eq!(pgm::pgm_nak_detect(&rp), pgm::PGM_NAK_ERR);
    // cc:143 VULN arm (checksum-zero skip face)
    let mut p = buf48();
    p[4] = 8;
    p[36] = 2;
    p[37] = 8;
    let rv = fw::RawData { data: &p, len: 48 };
    assert_eq!(pgm::pgm_nak_detect(&rv), pgm::PGM_NAK_VULN);
    // cc:139-:140 cksum-guard -> ERR (the fold rides the landed 18b
    // cksum_add; the vectors arm's NO-EV face is the transcript proof)
    let mut p = buf48();
    p[4] = 8;
    p[6] = 0xFF;
    p[7] = 0xFF;
    p[0] = 0x01;
    p[36] = 2;
    p[37] = 8;
    let rg = fw::RawData { data: &p, len: 48 };
    assert_eq!(pgm::pgm_nak_detect(&rg), pgm::PGM_NAK_ERR);
    // cc:146 OK arm (opt.len 200 >= data_left 12)
    let mut p = buf48();
    p[4] = 8;
    p[36] = 2;
    p[37] = 200;
    let ro = fw::RawData { data: &p, len: 48 };
    assert_eq!(pgm::pgm_nak_detect(&ro), pgm::PGM_NAK_OK);
    // cc:123 opt.type != 2 -> ERR (ground-only arm, never in vectors --
    // cited unit): type@4 == 8 but opt.type@36 == 3
    let mut p = buf48();
    p[4] = 8;
    p[36] = 3;
    let rt = fw::RawData { data: &p, len: 48 };
    assert_eq!(pgm::pgm_nak_detect(&rt), pgm::PGM_NAK_ERR);
    // the layout pin: the probe's len-44 ERR arm IS the cc:112
    // sizeof(PgmHeader) gate
    assert_eq!(pgm::PGM_HEADER_SIZE, 44);
}

// ==========================================================================
// 7. esp config-gate units (the decode_esp bool seam, both arms) +
//    the esp_params PT_BOOL "false" default face + EspModule::set
//    name-match arms (cc:58-:66; QUEUED provider face).
// ==========================================================================
#[test]
fn small4_esp_config_gate_units() {
    // esp_params: ONE decode_esp row + terminator (cc:42-:48); the
    // "false" default is the cc:100 gate face (ground grep-pinned).
    assert_eq!(esp::ESP_PARAMS.len(), 2);
    assert_eq!(esp::ESP_PARAMS[0].name, Some("decode_esp"));
    assert_eq!(
        esp::ESP_PARAMS[0].ptype,
        snort3::framework::parameter::Type::PtBool
    ); // cc:44 Parameter::PT_BOOL
    assert_eq!(esp::ESP_PARAMS[0].deflt, Some("false"));
    assert_eq!(esp::ESP_PARAMS[1].name, None);

    // EspModule::set arms (provider QUEUED): match -> Some(value),
    // non-match -> None (the cc:63 return false face)
    let m = esp::EspModule::new();
    assert_eq!(m.set("decode_esp", true), Some(true));
    assert_eq!(m.set("decode_esp", false), Some(false));
    assert_eq!(m.set("other", true), None);
    // the 3-arg ctor face: params Some(&ESP_PARAMS) (contrast the
    // pgm/auth 2-arg face, params None)
    assert!(m.base.params.is_some());
    let pm = pgm::PgmModule::new();
    assert!(pm.base.params.is_none());
    let am = ah::AuthModule::new();
    assert!(am.base.params.is_none());
    // the module NAMEs (vectors RULES lines): esp / pgm / auth
    assert_eq!(m.base.name, "esp");
    assert_eq!(pm.base.name, "pgm");
    assert_eq!(am.get_name(), "auth"); // the drift NAME face

    // gate-off full face: no event, NO mutation of the codec data
    let conf = SnortConfig::default();
    let z = buf96();
    let raw = fw::RawData { data: &z, len: 96 }; // LONG enough that only the gate can stop it
    let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ESP);
    let mut dd = esp::EspDecodeData::default();
    let mut ev = 0usize;
    let mut sink = |_: u32, _: u32| ev += 1;
    let b = esp::EspCodec::new().decode(&raw, &mut cd, &mut dd, false, &mut sink);
    assert!(!b);
    assert_eq!(ev, 0, "gate-off MUST raise zero events (vectors:1 face, cc:100-:101)");
    assert_eq!(cd.lyr_len, 0);
    assert_eq!(dd.decode_flags, 0);
}

// ==========================================================================
// 8. Static vocab pins — every numeric THIS row's decode ladders touch,
//    both ends decomposition-checked against the landed homes (the
//    build.sh python face mirrored Rust-side).
// ==========================================================================
#[test]
fn small4_static_vocab_pins() {
    // esp (cd_esp.rs homes): the 8+12+2 trio + PKT_TRUST
    assert_eq!(esp::ESP_HEADER_LEN + esp::ESP_AUTH_DATA_LEN + esp::ESP_TRAILER_LEN, 22);
    assert_eq!(esp::DECODE_PKT_TRUST, 32); // decode_data.h:140 (vectors:5 dflags=32)
    // frag (cd_frag.rs homes): MF|FRAG = 192; FRAG alone = 64
    assert_eq!(frag::DECODE_FRAG, 64); // decode_data.h:141
    assert_eq!(frag::DECODE_MF, 128); // decode_data.h:142
    assert_eq!(frag::DECODE_MF | frag::DECODE_FRAG, 192); // vectors:19 dflags=192
    // auth
    assert_eq!(ah::MIN_AUTH_LEN, 16); // cc:79 (vectors:37 short15 arm)
    // framework rides (resident): ENCAP pair, OOO, FINISHED, MIN_EXT_LEN
    assert_eq!(fw::CODEC_UNSURE_ENCAP, 2);
    assert_eq!(fw::CODEC_SAVE_LAYER, 4);
    assert_eq!(fw::CODEC_ENCAP_LAYER, 6); // 2|4 (vectors:4 flags=6)
    assert_eq!(fw::CODEC_IP6_EXT_OOO, 0x400); // vectors:9 6|0x400 = 1030
    assert_eq!(fw::CODEC_ENCAP_LAYER | fw::CODEC_IP6_EXT_OOO, 1030);
    assert_eq!(fw::protocol_id::FINISHED_DECODE, 256); // vectors:5/:19/:24 next=256
    assert_eq!(fw::ip::MIN_EXT_LEN, 8); // ipv6.h:32 (frag cc:52 guard)
    assert_eq!(fw::CODEC_DF, 1); // cc:74 clear target
    // PIDs (grep-pinned ground-side in build.sh)
    assert_eq!(fw::protocol_id::ESP, 50); // vectors:10 ESPPID 50
    assert_eq!(fw::protocol_id::FRAGMENT, 44); // vectors:25 FRAGPID 44
    assert_eq!(fw::protocol_id::PGM, 113); // vectors:34 PGMPID 113
    assert_eq!(fw::protocol_id::AUTH, 51); // vectors:45 AHPID 51
}
