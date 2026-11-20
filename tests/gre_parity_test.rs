//! Parity test for the row-18g cd_gre port — one ground TU
//! (ip/cd_gre.cc 366 L, md5 361de6ff6f7a75b10e040729875f9ba5 wc/md5
//! re-measured in gre PLAN §0 and asserted every build by
//! tools/gre_harness/build.sh :40-:41).
//!
//! Ground truth #1: `tools/gre_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 26 L NEVER edited, md5
//! 41bd7d1bdac01694eeda1f3e56869e77 (the -O0 == -O2 byte-ident pair
//! re-verified by the harness build.sh cmp arms: gate + BOTH vectors
//! faces, the third-stream O2 arm new at this row). WHOLE transcript
//! replays HERE line-for-line as ONE ordered session (per-index
//! assert_eq over want.len()==26 — ordered, never set-membership).
//! probe_dec.cc statement order == transcript order, the R6 var-first
//! posture mirrored (build.sh :311-:312 greps the C face: bool-var
//! decode assignment >= 8, printf.*->decode == 0) — the Rust replay
//! likewise stores every decode bool BEFORE the post-decode field
//! reads.
//!
//! Ground truth #2: `tools/gre_harness/vectors_faceA.txt` — the
//! FACE-A load face (probe.cc ONE-REAL-table walk through the
//! in-probe load_plugins witness), 5 L, md5
//! 783649440def7ec3b032970d223a8a6a — replayed as the SECOND ordered
//! session. mod_ctor/mod_dtor REAL pair (gre_api cc:326-:327) — the
//! honest contrast arm against the 18f teredo=0 asymmetry.
//!
//! Ground truth #3 (NEW at this row — the gate itself is a tracked
//! contract): `tools/gre_harness/gate.txt` — 3 L, md5
//! 6751d1a8c21da0fdfed87ddfd4d37c5f, the RUNNER's output of the
//! ground embedded TEST_CASE (:351-:366) compiled VERBATIM under the
//! shim route. This is the sanctioned chain change (first break after
//! 14 straight byte-ident 4826fc22 rows; the 9 legacy holders stay
//! frozen, TWO md5 lineages from here on, census MEASURED at build.sh
//! :401-:403). The tail line is runner-measured, NEVER typed docs-side
//! (17p rule) — the gre_gate_contract test pins the captured file,
//! and the ground case itself translates BELOW as ONE up_gate_* fn
//! (statement-for-statement, :352-:365; unlike the 18b/18f
//! CppUTest face the gate here actually RAN — receipt, not translation-only).
//!
//! Eval-order note: EV lines land between the decode call and the
//! summary printf exactly as the C sink prints them (queue_event
//! witness seam `EV %u %u` via GID_DECODE 116, the landed framework
//! codec_event — eth/ext/tun lineage). The bypass hook replay mirrors
//! tools/tun_harness/witness_18f.cc byte-exactly (carried witness,
//! ZERO new at 18g): observable table tun_mask + ground-shaped return
//! `!((mask & proto) or daq)`, daq arm pinned false; the mask arms
//! 0x40 / 0 re-arm exactly where probe_dec.cc calls
//! tun_witness_set_mask (GRE bit rides the SAME table — TUNNEL_GRE
//! 0x40 ground snort_config.h:125).
//!
//! Pins faced HERE (deviations row 18g): the encode SEQ-arm out-of-
//! window sequence write (C buf.data()+len runs past the allocated
//! window into the backing store; the window is what cksum_add sums,
//! zero contribution — the gated Rust form skips it, measured
//! byte-ident face); the SRE walk's unchecked C cursor reads (never
//! vector-armed: NO probe/replay arm sets ROUTE, gre build.sh carries
//! no ROUTE face); gre has NO PROTO_BIT__GRE ground-side (build.sh
//! :337-:339) -> the bits=0 face is BY CONSTRUCTION; the log() format
//! lands cited-but-never-vectorized (the probe never calls log()).

use snort3::codecs::cd_gre as gre;
use snort3::framework::codec as fw;

const VECTORS: &str = include_str!("../tools/gre_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/gre_harness/vectors_faceA.txt");
const GATE: &str = include_str!("../tools/gre_harness/gate.txt");

/// probe_dec.cc zeroed buffers (`uint8_t z[64]={0}`, f/k/q/v1/v2/v3/
/// bv/ok[16], back[16 for up]) — separate arrays, mutation order per
/// arm below. Verbatim posture.
fn buf64() -> [u8; 64] {
    [0u8; 64]
}
fn buf16() -> [u8; 16] {
    [0u8; 16]
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 26 lines, ordered,
//    one session (probe_dec.cc statement order, R6 var-first mirrored).
// ==========================================================================
#[test]
fn gre_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 26, "vectors.txt must hold the full 26-line DEC ladder");

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
    // the BYPASS seam: witness_18f.cc's ground-shaped body over the
    // observable table tun_mask (toggled per arm exactly where
    // probe_dec.cc calls tun_witness_set_mask): `!((tun_mask & proto)
    // or daq)`, daq pinned false (SFDAQ unlinked) — inline per call so
    // the table re-arms between arms (tun replay face).
    let mut tun_mask: u16 = 0;

    // probe_dec.cc:18-:20: the record face (API then HELP, "gre" tag on
    // both). vectors:1-:2 — the CDAPI carry 112/1900547 face (build.sh
    // :322 pins the DEC line) + the cc:41 help string (:325).
    {
        let a = gre::CD_GRE[0];
        push(format!(
            "API gre type={} size={} ver={} name={}",
            a.ptype, a.size, a.api_version, a.name
        ));
        push(format!("HELP gre {}", a.help));
    }
    let gg = gre::GreCodec::new(); // a->ctor(nullptr), probe_dec:21

    // -- decode arms (probe_dec.cc:23-:63; every bool stored BEFORE the
    //    printf face — R6) --
    {
        // probe_dec.cc:23-:25: RawData z len 3 < GRE_HEADER_LEN 4 ->
        // EV 160 (cc:169-:171) THEN false. vectors:3-:4 `GRE short3 -> 0`.
        let z = buf64();
        let raw = fw::RawData { data: &z, len: 3 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b0 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink); // R6: var first
        push(format!("GRE short3 -> {}", b0 as i32));
    }
    {
        // probe_dec.cc:27-:29: f[1]=0x08 -> get_version 0x08&0x07 = 0
        // CASE 0 but GRE_FLAGS(version&0xF8)=0x08 -> EV 163 (cc:187-
        // :189). vectors:5-:6.
        let mut f = buf16();
        f[1] = 0x08;
        let raw = fw::RawData { data: &f, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b1 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE v0-badflags -> {}", b1 as i32));
    }
    {
        // probe_dec.cc:32-:34: k[0]=0x80 CHKSUM -> len 4+4=8 (cc:193-
        // :194 the +CHKSUM+OFFSET single add) > raw 4 -> the SECOND
        // guard cc:274-:276 -> EV 160. vectors:7-:8.
        let mut k = buf16();
        k[0] = 0x80;
        let raw = fw::RawData { data: &k, len: 4 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b2 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE chksum-long -> {}", b2 as i32));
    }
    {
        // probe_dec.cc:36-:38: q[0]=0x10 SEQ -> len 4+4=8 > 4 -> same
        // second-guard face EV 160. vectors:9-:10.
        let mut q = buf16();
        q[0] = 0x10;
        let raw = fw::RawData { data: &q, len: 4 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b3 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE seq-long -> {}", b3 as i32));
    }
    {
        // probe_dec.cc:40-:42: v1[1]=0x09 -> version nibble 1,
        // GRE_V1_FLAGS(0x09 & 0x78)=0x08 hits the five-OR guard ->
        // EV 164 (cc:238-:241). vectors:11-:12.
        let mut v1 = buf16();
        v1[1] = 0x09;
        let raw = fw::RawData { data: &v1, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b4 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE v1-flags -> {}", b4 as i32));
    }
    {
        // probe_dec.cc:44-:46: v2[1]=0x01, etype 0 != 0x880B PPP ->
        // EV 164 second arm (cc:246-:248). vectors:13-:14.
        let mut v2 = buf16();
        v2[1] = 0x01;
        let raw = fw::RawData { data: &v2, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b5 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE v1-badetype -> {}", b5 as i32));
    }
    {
        // probe_dec.cc:48-:50: v3 PPP type 0x880B but flags KEY clear ->
        // EV 164 third arm (cc:253-:255). vectors:15-:16.
        let mut v3 = buf16();
        v3[1] = 0x01;
        v3[2] = 0x88;
        v3[3] = 0x0B;
        let raw = fw::RawData { data: &v3, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b6 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE v1-nokey -> {}", b6 as i32));
    }
    {
        // probe_dec.cc:52-:54: bv[1]=0x02 -> default switch arm ->
        // EV 162 (cc:269-:270). vectors:17-:18.
        let mut bv = buf16();
        bv[1] = 0x02;
        let raw = fw::RawData { data: &bv, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b7 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE badver2 -> {}", b7 as i32));
    }
    {
        // probe_dec.cc:57-:60: v1-ok decode OK: ok = FLAGS KEY 0x20,
        // version 0x01, etype 0x880B -> len 4+KEY 4 = 8 <= raw 10 ->
        // the bypass pair (tun_witness_set_mask(0x40) -> TUNNEL_GRE
        // 0x40 bit SET -> bypass FALSE -> tunnel_bypass stays false).
        // lyr 8 (cc:283), next 34827 = the gre_proto BE face of 0x880B
        // (build.sh :344-:353 decomposes both ends at ground
        // protocol_ids.h:152), bits 0 (NO PROTO_BIT__GRE ground-side —
        // build.sh :337-:339, by-construction face), flags 4608 =
        // CODEC_NON_IP_TUNNEL 0x0200 | CODEC_ETHER_NEXT 0x1000
        // (cc:285, ground codec.h:104/:106 build.sh-asserted).
        // vectors:19.
        tun_mask = 0x40; // probe_dec.cc:58
        let mut ok = buf16();
        ok[0] = 0x20;
        ok[1] = 0x01;
        ok[2] = 0x88;
        ok[3] = 0x0B;
        let raw = fw::RawData { data: &ok, len: 10 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b8 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!(
            "GRE mask0040 -> {} bypass={} lyr={} next={} bits={} flags={}",
            b8 as i32,
            cd.tunnel_bypass as i32,
            cd.lyr_len,
            cd.next_prot_id,
            cd.proto_bits,
            cd.codec_flags
        ));
    }
    {
        // probe_dec.cc:61-:63: same fixture, tun_witness_set_mask(0) —
        // the ground NSDMI tunnel_mask=0 face -> bypass TRUE ->
        // tunnel_bypass set. vectors:20.
        tun_mask = 0; // probe_dec.cc:61
        let mut ok = buf16();
        ok[0] = 0x20;
        ok[1] = 0x01;
        ok[2] = 0x88;
        ok[3] = 0x0B;
        let raw = fw::RawData { data: &ok, len: 10 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let b9 = gg.decode(&raw, &mut cd, &mut |_sid| !((tun_mask & _sid) != 0), &mut sink);
        push(format!("GRE mask0000 -> {} bypass={}", b9 as i32, cd.tunnel_bypass as i32));
        // probe_dec.cc:64 re-arms tun_witness_set_mask(0) AFTER the
        // pair — no later arm reads the mask, so that replay line lands
        // nowhere observable (comment, not a statement).
    }
    {
        // probe_dec.cc:65: get_protocol_ids -> GRE 47
        // (protocol_ids.h:66/:102, build.sh :355 pins `GRE = 47,` on the
        // LANDED protocol_id::GRE home). vectors:21.
        let mut gv: Vec<fw::ProtocolId> = Vec::new();
        gg.get_protocol_ids(&mut gv);
        push(format!("GREPID {} n={}", gv[0], gv.len()));
    }
    {
        // probe_dec.cc:67-:68: mod_ctor -> get_rules census (gre_rules
        // cc:45-:54 SIX rows + terminator; build.sh :359 ground grep
        // count 6) -> rules=6 sid0=160 name=gre; mod_dtor drop (stack-
        // owned, 18d posture). vectors:22.
        let nm = gre::GreModule::new();
        let nr = gre::GreModule::get_rules();
        let ncc = snort3::codecs::codec_module::rule_count(nr);
        push(format!("GRE rules={} sid0={} name={}", ncc, nr[0].sid, nm.get_name()));
    }
    {
        // probe_dec.cc:69: `nb->mod_ctor?1:0, nb->mod_dtor?1:0` — the
        // REAL mod pair (gre_api cc:326-:327). vectors:23.
        let nb = gre::CD_GRE[0];
        push(format!(
            "GRE api mod_ctor={} mod_dtor={}",
            nb.mod_ctor as i32,
            nb.mod_dtor as i32
        ));
    }
    {
        // probe_dec.cc:72-:76: THE GROUND TEST_CASE's OWN SUBJECT face —
        // 1-byte backing Buffer (Buffer buf(&t, 1)), raw_len
        // GRE_HEADER_LEN+1 = 5: cc:130-:131 `!buf.allocate(5)` fails
        // ((end 0 + 5) > max_len 1) -> false, enc untouched. This is
        // the SAME arm the gate's single CHECK pins green (gate.txt
        // line 2, one assertion) — the Rust twin test
        // up_gate_gre_raw_len_gt_header_len below. vectors:24.
        let mut t = [0u8; 1];
        let mut buf = fw::Buffer::new(&mut t, 1);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_VAL, fw::ip_protocol::GRE, 0, 0);
        let raw_in = [0u8; 1]; // :354 the single 0 byte the probe passes
        let ef = gg.encode(&raw_in, 5, &mut enc, &mut buf);
        push(format!("ENC lt-grehdr -> {}", ef as i32));
    }
    {
        // probe_dec.cc:77-:86: the allocate-OK face -- BACKING base+32,
        // Buffer buf2(p, 32) so allocate(8) moves base back INSIDE the
        // backing store (codec.h Buffer face, our Buffer::new pins the
        // same arithmetic); flags 0x90 = CHKSUM|SEQ, etype 0x0800.
        // SEQ arm: C len walk 4 +CHKSUM 4 -> 8; the sequence read/write
        // slot sits at window offset 8 -- JUST PAST the 8-byte window,
        // inside the backing zeros (deviations row 18g: the gated Rust
        // form skips the out-of-window C write, ZERO contribution to
        // every observed face -- the backing zeros below pin it).
        // CHKSUM arm: cksum_add over buf.size() = 8 window bytes
        // [90,00,08,00,00,00,00,00] -> 0x0090+0x0008 = 0x98 -> fold ->
        // ~ -> 0xff67 -> LE write-back 103 255 (cc:159-:161).
        // enc next_proto 47 / next_ethertype 0x0800 = 2048 (cc:135-:136
        // greh_out->proto() = ntohs of the wire [08,00]). vectors:25.
        let mut back = [0u8; 64];
        let (eg, cb0, cb1, nproto, netype) = {
            let p = &mut back[32..]; // the probe's p = back+32 face
            let mut buf2 = fw::Buffer::new(p, 32);
            let mut cin = [0u8; 8];
            cin[0] = 0x90;
            cin[1] = 0x00;
            cin[2] = 0x08;
            cin[3] = 0x00;
            let mut enc2 = fw::EncState::new(fw::ENC_FLAG_VAL, fw::ip_protocol::GRE, 0, 0);
            let eg = gg.encode(&cin, 8, &mut enc2, &mut buf2); // cc:130 gate passes
            let d = buf2.data().expect("allocate-ok window valid");
            // probe_dec.cc:85 reads *(buf2.data()+4/+5) AFTER encode:
            let cb0 = d[4];
            let cb1 = d[5];
            (eg, cb0, cb1, enc2.next_proto, enc2.next_ethertype)
        };
        push(format!(
            "ENC ok -> {} cksum-bytes {} {} nproto={} netype={}",
            eg as i32, cb0, cb1, nproto, netype
        ));
        // the pinned substitution face: Buffer(base = one PAST the
        // store end, codec.h ctor) + allocate(8) -> base 32->24 -> the
        // live window is back[56..64]: the copied wire [90,00,08,00]
        // + the cksum write-back [67,ff] at 58-59 (LE of ~0x98) + the
        // last two window bytes zero (the C sequence write slot sits
        // at window offset 8 = JUST PAST the end -- the gated Rust
        // form skips it, and every byte the vectors observe is
        // window-local, so the skip is zero-contribution). The whole
        // rest of the backing stays all-zero.
        assert_eq!(&back[56..64], &[0x90, 0x00, 0x08, 0x00, 0x67, 0xff, 0x00, 0x00]);
        assert!(back[..56].iter().all(|&b| b == 0));
    }
    {
        // probe_dec.cc:89-:91: update() chksum face — up[0]=0x80,
        // lyr 8, ul 0 -> cc:114 ul = 8 FIRST; CHKSUM arm zeroes up[4..6]
        // (uint16 LE memcpy clears BOTH bytes), cksum_add over the
        // updated_len window (16-byte buffer, declared len 8):
        // [80,00,00,00 | 00,00,00,00] -> 0x0080 -> ~ -> 0xff7f -> LE:
        // up[4]=127 up[5]=255. vectors:26. THE FIRST C->Rust cross-row
        // checksum::cksum_add consumer (csum row 18b face).
        let mut up = buf16();
        up[0] = 0x80;
        let mut ul: u32 = 0;
        gg.update(&(), fw::ENC_FLAG_VAL, &mut up, 8, &mut ul); // UNUSED(api), flags never read
        push(format!("UPD chksum-bytes {} {} ul={}", up[4], up[5], ul));
    }

    for (i, (got, want_line)) in out.borrow().iter().zip(want.iter()).enumerate() {
        assert_eq!(got, want_line, "DEC transcript line {}", i + 1);
    }
    assert_eq!(out.borrow().len(), 26, "replay must emit exactly 26 lines");
}

// ==========================================================================
// 2. FACE-A load-face replay — vectors_faceA.txt 5 lines, ordered
//    (probe.cc ONE-table walk of the REAL cd_gre through the in-probe
//    load_plugins witness; the probe pulls NO codec_api object —
//    ext/tun nm rule carried at gre build.sh :266).
// ==========================================================================
#[test]
fn gre_face_a_load_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 5, "vectors_faceA.txt must hold the full 5-line load ladder");

    let mut out: Vec<String> = Vec::new();
    // probe.cc:14 PluginManager::load_plugins(cd_gre) through the
    // in-probe witness (`for (; p && *p; ++p) printf("LOAD %s\n",
    // (*p)->name)`) — the REAL name, dormant ladder untouched.
    for rec in gre::CD_GRE {
        out.push(format!("LOAD {}", rec.name));
    }
    out.push("LOADS 1".to_string()); // probe.cc:15
    // probe.cc:17-:19 BaseApi record face + the cc:41 help (NO "gre"
    // tag on this face — probe noise vs the DEC face, the printed
    // expression wins, build.sh :320-:323 pins). vectors:3-:4.
    let a = gre::CD_GRE[0];
    out.push(format!(
        "API gre type={} size={} ver={} name={}",
        a.ptype, a.size, a.api_version, a.name
    ));
    out.push(format!("HELP {}", a.help));
    // probe.cc:20 the REAL mod pair (the honest contrast arm vs the
    // 18f teredo=0 face). vectors:5.
    out.push(format!(
        "GRE mod_ctor={} mod_dtor={}",
        a.mod_ctor as i32,
        a.mod_dtor as i32
    ));

    for (line, (got, want_line)) in out.iter().zip(want.iter()).enumerate() {
        assert_eq!(got, want_line, "FACE-A transcript line {}", line + 1);
    }
    assert_eq!(out.len(), 5, "FACE-A replay must emit exactly 5 lines");
}

// ==========================================================================
// 3. GATE contract — the tracked gate.txt (6751d1a8... md5-pinned at
//    gre build.sh :380, wc 3 at :381) is the THIRD pinned contract of
//    this row: the ground [cd_gre] case, RUNNER tail verbatim. The C++
//    gate RAN (shim route, receipt not translation-only); this test
//    pins the captured artifact against drift from the Rust side too
//    (md5 census of the two lineages lives in build.sh :401-:403).
// ==========================================================================
#[test]
fn gre_gate_contract() {
    let lines: Vec<&str> = GATE.lines().collect();
    assert_eq!(lines.len(), 3, "gate.txt holds the runner transcript (3 lines)");
    assert_eq!(
        lines[1],
        "All tests passed (1 assertion in 1 test case)",
        "gate tail must stay the RUNNER's wording for the ONE ground case (1 assertion) — the new chain anchor"
    );
    // The -l face (case name + [cd_gre] tag) is build.sh-asserted at
    // :254-:255 against the gate binary; here the tail + the ONE-
    // assertion count is the Rust-side face of the same receipt.
    assert_eq!(lines[0].chars().filter(|&c| c == '=').count(), 79, "Catch banner");
}

// ==========================================================================
// 4. Upstream-suite translation — the embedded ground Catch case
//    (:351-:366, ONE TEST_CASE, ONE CHECK at :364) statement-for-
//    statement. The C gate RUNS green (gate.txt); this is the Rust
//    twin of the same case, fixture literals byte-for-byte (18b
//    up_gate pattern, the first codec row where the gate is REAL --
//    gre PLAN §4/§8).
// ==========================================================================
#[test]
fn up_gate_gre_raw_len_gt_header_len() {
    // GreCodec grecodec;                                    :353
    let grecodec = gre::GreCodec::new();
    // const uint8_t raw_in = 0;                              :354
    let raw_in = [0u8; 1];
    // uint8_t raw_len = GRE_HEADER_LEN + 1;                  :355 (5)
    let raw_len: u16 = (gre::GRE_HEADER_LEN + 1) as u16;
    // ip::IpApi ip_api;  EncState enc(ip_api, ENC_FLAG_VAL,
    //     IpProtocol::GRE, 0, 0);                             :356-:357
    // (the C EncState ctor keeps the const IpApi& ref as its first
    // arg — the landed EncState::new drops the ref, dsize/ttl
    // operands carried positionally)
    let mut enc = fw::EncState::new(fw::ENC_FLAG_VAL, fw::ip_protocol::GRE, 0, 0);
    // uint16_t size = 1;  uint8_t t = 0;  Buffer buf(&t, size); :358-:360
    let mut t = [0u8; 1];
    let mut buf = fw::Buffer::new(&mut t, 1);
    // Flow *flow = nullptr;                                   :361 — the
    // never-written operand is UNNAMED in the Rust signature (cc:128).
    // CHECK (false == grecodec.encode(&raw_in, raw_len, enc, buf,
    //     flow));                                             :364
    assert!(
        !grecodec.encode(&raw_in, raw_len, &mut enc, &mut buf),
        "cc:130-:131 allocate gate: 5 > the 1-byte Buffer max_len -> false (the CHECK the gate pins green)"
    );
    // Post-state pin (the CHECK's face, never a C statement): the
    // failed-allocate Buffer keeps end 0 -> data() None (codec.h
    // zero-size-invalid rule the landed Buffer models) and enc stays
    // untouched (next_proto is the ctor init GRE, NOT a cc:135 write).
    assert!(buf.data().is_none());
    assert_eq!(buf.size(), 0);
    assert_eq!(enc.next_proto, fw::ip_protocol::GRE);
}

// ==========================================================================
// 5. Row-scoped vocab faces: the cc:90-:98 flag macros + the gre.h
//    accessor face (md5-verified 50-L fresh cp; raw_proto kept as a
//    doc-pinned never-vector arm). Cites per arm.
// ==========================================================================
#[test]
fn gre_flag_macros_and_hdr_face() {
    // gre.h:30-:34 layout face + :36-:45 accessors.
    let pkt = [0x28u8, 0x89, 0x88, 0x0B]; // flags 0x28, version 0x89, BE type 0x880B
    assert_eq!(gre::hdr_flags(&pkt), 0x28); // gre.h:32
    assert_eq!(gre::hdr_version(&pkt), 0x89); // gre.h:33
    assert_eq!(gre::gre_get_version(&pkt), 0x89 & 0x07); // gre.h:36-:38 -> 1
    assert_eq!(gre::gre_proto(&pkt), 0x880B); // gre.h:39-:41 ntohs face
    assert_eq!(gre::gre_raw_proto(&pkt), 0x0B88); // gre.h:43-:45 raw slot (LE u16 of wire pair)

    // cc:90-:98 macros over the two bytes, per-bit singles:
    assert_eq!(gre::gre_v1_flags(0x89), 0x08); // 0x89 & 0x78
    assert_eq!(gre::gre_v1_ack(0x89), 0x80); // 0x89 & 0x80
    assert_eq!(gre::gre_chksum(0x28), 0x00); // 0x28 & 0x80
    assert_eq!(gre::gre_route(0x28), 0x00);
    assert_eq!(gre::gre_key(0x28), 0x20); // 0x28 & 0x20
    assert_eq!(gre::gre_seq(0x28), 0x00);
    assert_eq!(gre::gre_ssr(0x28), 0x08); // 0x28 & 0x08
    assert_eq!(gre::gre_recur(0x28), 0x00);
    assert_eq!(gre::gre_flags(0x89), 0x88); // 0x89 & 0xF8
    // cc:79-:88 constant census (the TEST_CASE subject rides :79):
    assert_eq!((gre::GRE_HEADER_LEN, gre::GRE_CHKSUM_LEN, gre::GRE_OFFSET_LEN), (4, 2, 2));
    assert_eq!((gre::GRE_KEY_LEN, gre::GRE_SEQ_LEN, gre::GRE_SRE_HEADER_LEN, gre::GRE_V1_ACK_LEN), (4, 4, 4, 4));
    // snort_config.h:125 pin (NEVER typed -- face against the other
    // carried masks, snort_config.h:119-:128 as witness_18f rides them).
    assert_eq!(gre::TUNNEL_GRE, 0x40);
}

// ==========================================================================
// 6. rules-table census — cc:45-:54 verbatim msgs, the six resident
//    CodecSid enumerators (codec_module.rs:107-:112, h:93-:98) and the
//    table-only rows 161/165 (no codec_event call site touches them —
//    measured ground fact).
// ==========================================================================
#[test]
fn gre_rules_census() {
    let r = gre::GRE_RULES;
    assert_eq!(r.len(), 7); // six + cc:53 terminator
    let sids: Vec<u32> = r[..6].iter().map(|e| e.sid).collect();
    assert_eq!(sids, vec![160, 161, 162, 163, 164, 165]);
    let msgs: Vec<Option<&str>> = r[..6].iter().map(|e| e.msg).collect();
    assert_eq!(
        msgs,
        vec![
            Some("GRE header length > payload length"), // cc:47
            Some("multiple encapsulations in packet"), // cc:48
            Some("invalid GRE version"), // cc:49
            Some("invalid GRE header"), // cc:50
            Some("invalid GRE v.1 PPTP header"), // cc:51
            Some("GRE trans header length > payload length"), // cc:52
        ]
    );
    let term = &r[6];
    assert_eq!(term.sid, 0);
    assert!(term.msg.is_none()); // cc:53 { 0, nullptr }
    assert_eq!(snort3::codecs::codec_module::rule_count(&r), 6); // vectors:22 rules=6
}

// ==========================================================================
// 7. Record census — gre_api (:315-:335) presence face, vectors:1 +
//    vectors:23 + vectors_faceA:3/:5.
// ==========================================================================
#[test]
fn gre_record_census() {
    let a = gre::GRE_API;
    assert_eq!(a.ptype, fw::PT_CODEC); // cc:318
    assert_eq!(a.size, fw::CDAPI_SIZEOF_CODEC_API); // cc:319 == 112 probe pin
    assert_eq!(a.api_version, fw::CDAPI_VERSION); // cc:320 == 1900547
    assert_eq!(a.version, 0); // cc:321
    assert_eq!(a.features, fw::PLUGIN_SO_RELOAD); // cc:322
    assert_eq!(a.options, fw::API_OPTIONS); // cc:323
    assert_eq!(a.name, "gre"); // cc:324
    assert_eq!(a.help, "support for generic routing encapsulation"); // cc:325, vectors:2
    assert!(a.mod_ctor && a.mod_dtor); // cc:326-:327 SET (vectors:23 + faceA:5)
    assert!(!a.pinit && !a.pterm && !a.tinit && !a.tterm); // cc:329-:332 nullptr quartet
    assert!(a.ctor && a.dtor); // cc:333-:334
    // table face cc:337-:345 (non-BUILDING_SO arm; TRUE name, the row
    // has NO cd_hop_opts drift tripwire):
    assert_eq!(gre::CD_GRE.len(), 1);
    let t0 = gre::CD_GRE[0];
    assert_eq!(t0.name, a.name);
    assert_eq!(t0.size, a.size);
    assert_eq!(t0.api_version, a.api_version); // the table head IS the gre_api record (cc:343)
}

// ==========================================================================
// 8. ladder tripwire — "cd_gre" ALREADY resident in
//    STATIC_CODEC_EXTERN_NAMES (codec_api.rs:110, between cd_geneve
//    and cd_gtp in cc order): the row re-touches NOTHING there; this
//    tripwire pins the census so a later rename must answer HERE.
// ==========================================================================
#[test]
fn gre_static_names_tripwire() {
    let names = snort3::codecs::codec_api::STATIC_CODEC_EXTERN_NAMES;
    assert_eq!(names.len(), 34, "the cc-order 34-ladder stays its size (18c census)");
    let i = names.iter().position(|n| *n == "cd_gre").expect("cd_gre resident");
    assert_eq!(names[i - 1], "cd_geneve"); // 18f resident neighbor
    assert_eq!(names[i + 1], "cd_gtp"); // cc order held
    assert_eq!(names.iter().filter(|n| **n == "cd_gre").count(), 1);
    // the TRUE-NAME face: table const == the ladder name == ground cc:340
    // extern (gre build.sh :51-:53 sed-pins the arms).
    assert_eq!(gre::CD_GRE[0].name, "gre");
}

// ==========================================================================
// 9. encode SEQ-arm in-window unit face (NEVER vectorized — the probe
//    SEQ/CHKSUM face parks the sequence read OUT of the window, see
//    test 1 + deviations; this arms the cc:138-:152 loop body fully):
//    flags CHKSUM|KEY|SEQ (0xB0): the C len walk = 4 +4(CHKSUM)
//    +4(KEY) = 12, so the sequence slot sits at window offset 12 >=
//    12 -> IN-window: u32 net-order +1 round trip (cc:148-:151
//    memcpy/htonl/ntohl), then the CHKSUM rewrite. Fixture stays a
//    defined one (the C arm runs fully IN-window for these flags —
//    no substitution involved).
// ==========================================================================
#[test]
fn gre_encode_seq_unit() {
    let mut back = [0u8; 32];
    let p = &mut back;
    // wire fixture (own probe fixture, NOT a vectors line): flags
    // 0xB0, version 0, etype 0x0000, key slot zeros, sequence at
    // window offset 12 (net-order 0x00000001 -> +1 = 2).
    let mut cin = [0u8; 16];
    cin[0] = 0xB0; // CHKSUM|KEY|SEQ
    let seq_at = 12; // C len walk 4 +4(CHKSUM cc:142) +4(KEY cc:145)
    // the net-order sequence rides the INPUT: cc:134's memcpy lands it
    // in the window BEFORE the SEQ arm reads it back at cc:149.
    cin[seq_at] = 0x00;
    cin[seq_at + 1] = 0x00;
    cin[seq_at + 2] = 0x00;
    cin[seq_at + 3] = 0x01;
    // Buffer(&back(32), 16) face: allocate(16) moves base 16->0 -> the
    // window is back[0..16] (same codec.h Buffer arithmetic).
    let mut buf = fw::Buffer::new(p, 16);
    let mut enc = fw::EncState::new(fw::ENC_FLAG_VAL, fw::ip_protocol::GRE, 0, 0);
    let okc = snort3::codecs::cd_gre::GreCodec::new().encode(&cin[..16], 16, &mut enc, &mut buf);
    assert!(okc);
    let d = buf.data().expect("valid window");
    // seq +1 net-order round trip (cc:150), BEFORE the cksum recompute
    // (cc:154-:162 re-sums the MUTATED bytes):
    assert_eq!(&d[seq_at..seq_at + 4], &[0x00, 0x00, 0x00, 0x02]);
    // the cksum field 4-5 is zeroed then rewritten over the window —
    // pin against the landed 18b primitive directly, the C pair
    // (cc:159-:161): after the +1 write, zero 4-5 and sum:
    let mut w = d.to_vec();
    w[4] = 0;
    w[5] = 0;
    let expect = snort3::codecs::checksum::cksum_add(&w, w.len());
    assert_eq!(u16::from_le_bytes([d[4], d[5]]), expect);
    assert_eq!(enc.next_proto, fw::ip_protocol::GRE); // cc:135
    assert_eq!(enc.next_ethertype, 0x0000); // cc:136 over the fixture etype
}

// ==========================================================================
// 10. decode walk units (NEVER vectorized arms, cited): the v0
//     KEY/CHKSUM add arithmetic and the SECOND long-guard boundary
//     (len == raw.len passes, len == raw.len+1 fires EV 160), the v1
//     SEQ/ACK walk totals, and the default-arm mask face
//     (get_version's & 0x07 admits ONLY 0/1 as cases -- version 2-7
//     all ride EV 162; the cc:183 switch has exactly those arms).
// ==========================================================================
#[test]
fn gre_decode_walk_units() {
    let mut sink = |_gid: u32, _sid: u32| {}; // silent (probe never arms these faces)
    let gc = gre::GreCodec::new();
    let mut bypass_off = |_sid: u16| false;

    // v0: CHKSUM sets +4 (2+2), KEY sets +4 -> len 12 exact at raw 12
    // -> the cc:274 guard passes (len > raw.len only): success, lyr 12.
    let mut f = [0u8; 16];
    f[0] = 0xA0; // CHKSUM|KEY
    let raw = fw::RawData { data: &f, len: 12 };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
    assert!(gc.decode(&raw, &mut cd, &mut bypass_off, &mut sink)); // cc:193-:197
    assert_eq!(cd.lyr_len, 12);

    // same fixture raw 11 -> len 12 > 11 -> EV 160 second guard
    // (cc:274-:277, vectors:7/:9 sibling face at len 8).
    let raw = fw::RawData { data: &f, len: 11 };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
    let mut ev: Vec<(u32, u32)> = Vec::new();
    {
        let mut esink = |g: u32, s: u32| ev.push((g, s));
        assert!(!gc.decode(&raw, &mut cd, &mut bypass_off, &mut esink));
    }
    assert_eq!(ev, vec![(116, 160)]);

    // v1 SEQ + V1_ACK walk: flags KEY|SEQ (0x30), version 0x81 (ACK
    // bit set, type PPP): len 4+4(KEY)+4(SEQ)+4(ACK) = 16 (cc:259-:265).
    let mut g = [0u8; 24];
    g[0] = 0x30;
    g[1] = 0x81;
    g[2] = 0x88;
    g[3] = 0x0B;
    let raw = fw::RawData { data: &g, len: 16 };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
    assert!(gc.decode(&raw, &mut cd, &mut bypass_off, &mut sink));
    assert_eq!(cd.lyr_len, 16);

    // version byte 0x02..0x07 -> get_version = 2..7 -> default arm
    // EVERY one (mask face, never a case): census EV 162 x6.
    for vb in 0x02u8..=0x07 {
        let mut h = [0u8; 8];
        h[1] = vb;
        let raw = fw::RawData { data: &h, len: 8 };
        let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
        let mut ev: Vec<(u32, u32)> = Vec::new();
        {
            let mut esink = |g: u32, s: u32| ev.push((g, s));
            assert!(!gc.decode(&raw, &mut cd, &mut bypass_off, &mut esink));
        }
        assert_eq!(ev, vec![(116, 162)], "version byte {vb:#04x} must ride the default arm");
    }

    // SRE walk face (cc:204-:231, NEVER vector-armed -- gre probe
    // carries NO ROUTE arm; here the ROUTE-SET walk is walked to its
    // cc:212 bound-break: 4+4 (CHKSUM/ROUTE pair) + SRE slot 4 then an
    // all-zero terminator at cursor 8): ROUTE 0x40: len 4 -> +4
    // (CHKSUM||ROUTE add) -- operand identity -- +4 = 8; walk: len +4
    // = 12 > raw 12? NO: 12 <= 12 reads the terminator (addrfamily
    // 0, length 0 at cursor 8+... : sre_ptr starts at len == 8; skip
    // 2+1 reads bytes 8,9 / 10 / 11 inside bounds) -> all-zero break,
    // len stays 12 -> success lyr 12.
    let mut j = buf16();
    j[0] = 0x40; // ROUTE only
    let raw = fw::RawData { data: &j, len: 12 };
    let mut cd = fw::CodecData::new(None, fw::protocol_id::GRE);
    assert!(gc.decode(&raw, &mut cd, &mut bypass_off, &mut sink));
    assert_eq!(cd.lyr_len, 12);
}

// ==========================================================================
// 11. log() face (cited unit, NEVER vectorized -- the probe never
//     calls log(); the 18d eth posture): the cc:294 format string
//     VERBATIM, %u / %02X / (0x%04X) with the PARENS part of the
//     ground string, static_cast<uint16_t>(proto()).
// ==========================================================================
#[test]
fn gre_log_format_unit() {
    let mut lines: Vec<String> = Vec::new();
    let gre_hdr = [0x28u8, 0x89, 0x88, 0x0B];
    gre::GreCodec::new().log(&mut |s: String| lines.push(s), &gre_hdr);
    assert_eq!(lines.len(), 1);
    // get_version 0x89&0x07 = 1; flags 0x28; proto 0x880B -> the
    // ground format's three fields, decimal/upper-hex/parens.
    assert_eq!(lines[0], "version:1 flags:0x28 ethertype:(0x880B)");
}
