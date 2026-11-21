//! Parity test for the row-18o codecs/link cd_mpls.rs port — ground link/
//! cd_mpls.cc 390 L md5 e2911ad515d5f416415acd1ee9967379 (wc 390 + the
//! six-file LINK CHAPTER LEDGER 390+236+235+187+207+210 = 1465 re-measured
//! and asserted EVERY build by tools/mpls_harness/build.sh — the chapter
//! CLOSES at this file). ZERO-gate row (the 25th straight honest face; the
//! 19a-docs lineage count per harness PLAN §11(h), re-pinned at the row):
//! link/test find-0 + add_cpputest 0 + TEST_CASE/CppUTest grep-0 in the TU.
//!
//! Ground truth #1: `tools/mpls_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 54 L md5 b4b660e448703b603755a0049c6a2052 NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session. THE sid band FIRES POSITIVE in its OWN vectors THE FIRST TIME
//! (the q4 NEVER-land census FLIPS AT its own row): 34 EV lines ==
//! 170x2 171x2 172x1 173x1 174x1 175x26 176x1 (the python census face
//! re-derived Rust-side THIS pass — the {170..176} band AND the per-arm
//! counts), and the SAME band stays grep-0 in ALL FOUR landed predecessor
//! vectors (link4 + link6 + erspan + misc9, BOTH faces each — the flip
//! NEVER leaks; pinned below). THE R6 EVAL-ORDER RULE REPLAYS: every
//! decode bool lands in a var BEFORE the summary line and every
//! `EV 116 <sid>` lands between the decode call and its printf, NEVER
//! sorted. The interleave IS the pin set: M8 = 175x7 THEN 174 (the :181-
//! per-entry-before-:186-capture receipt), M10 = 175x5 THEN 176 (capture
//! BEFORE the depth clear), M15 = 175x2 THEN 170 (the drain face a tail-
//! count rule MISSES).
//!
//! THE DECIMAL GROUNDS (re-derived from protocol_ids.h — the seed-draft
//! DRIFT face 34781/25946 NEVER appears; tripwired below): ip6 34525 /
//! bridging 25944 / ip4 2048 / mpls-unicast init 34887 / multicast 34888 /
//! MPLS_IP 137 / pb 512 (PROTO_BIT__MPLS RESIDENT rtn_checks.rs :34 —
//! REUSED, never re-declared at the row).
//!
//! Ground truth #2: `tools/mpls_harness/vectors_faceA.txt` — the FACE-A
//! load/walk face (probe.cc over the ONE hidden-BUILDING_SO TRUE-NAME
//! table cd_mpls[] :385), 17 L md5 3066fc335fb21777891271b9c7b152c5: LOAD/
//! LOADS 1 x1 + API/HELP (the :34/:35 CORRECTED name/help face) + mod arms
//! REAL 1/1 + ctor/dtor SET + the DETERMINISTIC emplace-x3 GETIDS block
//! (contrast 18n's vlan unordered-SET: positional pins HERE, ORDER-PINNED
//! per probe.cc:13-17) + NAME/RULES n=7 170..176 + the PARAM inline raw-
//! field walk (PT_INT=4 / PT_ENUM=11 ordinals, the misc9 walk precedent) +
//! THE binding-driven SET ret=111 face + CTOR_M ok=1 (the config-carrying
//! ctor(m) :347 census).

use snort3::codecs::cd_mpls as ml;
use snort3::codecs::codec_api as capi;
use snort3::codecs::codec_module as cmmod;
use snort3::detection::rtn_checks;
use snort3::framework::codec as fw;
use snort3::framework::parameter::Type as PtType;
use snort3::framework::value::Value;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/mpls_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/mpls_harness/vectors_faceA.txt");

// The FOUR landed predecessor harness faces (frozen; the NEVER-land band
// greps stay TRUE there — the q4 flip is LOCAL to this row).
const L4_DEC: &str = include_str!("../tools/link4_harness/vectors.txt");
const L4_FA: &str = include_str!("../tools/link4_harness/vectors_faceA.txt");
const L6_DEC: &str = include_str!("../tools/link6_harness/vectors.txt");
const L6_FA: &str = include_str!("../tools/link6_harness/vectors_faceA.txt");
const ESP_DEC: &str = include_str!("../tools/erspan_harness/vectors.txt");
const ESP_FA: &str = include_str!("../tools/erspan_harness/vectors_faceA.txt");
const M9_DEC: &str = include_str!("../tools/misc9_harness/vectors.txt");
const M9_FA: &str = include_str!("../tools/misc9_harness/vectors_faceA.txt");

// The tun_harness witness_18f mask OBSERVABLE mirrored driver-side (the
// vectors' M16/M17 mask pair; the witness face `!(mask & proto)`) — a test
// FIXTURE, NEVER a port-side provider: the port seam stays the landed
// left-open bypass closure (cd_vxlan/cd_gtp/cd_geneve precedent).
fn tun_witness(mask: u16) -> impl FnMut(u16) -> bool {
    move |proto: u16| (mask & proto) == 0
}

// The probe scope face: FRESH CodecData (init_prot ETHERTYPE_MPLS_UNICAST
// 34887 — probe_dec every block) + FRESH DecodeData (mplsHdr value-init
// {}, decode_data.h :177) per decode, bool var FIRST (R6).
fn probe_run<'c>(
    codec: &ml::MplsCodec,
    bytes: &[u8],
    len: u32,
    conf: &'c SnortConfig,
    sink: fw::QueueSink<'_>,
    bypass: &mut dyn FnMut(u16) -> bool,
) -> (bool, fw::CodecData<'c>, ml::MplsHdr) {
    let mut cdd = fw::CodecData::new(Some(conf), ml::ETHERTYPE_MPLS_UNICAST);
    let mut d = ml::MplsHdr::default();
    let raw = fw::RawData { data: bytes, len };
    let b = codec.decode(&raw, &mut cdd, &mut d, sink, bypass);
    (b, cdd, d)
}

// The config-forced reserved-label matrix face: MplsModule + payload_type
// bound via the landed Value::set_param + the ctor(Some) thread (the
// faceA/fmod V2-set precedent).
fn cfg_run<'c>(
    bytes: &[u8],
    plt: u8,
    conf: &'c SnortConfig,
    sink: fw::QueueSink<'_>,
    bypass: &mut dyn FnMut(u16) -> bool,
) -> (bool, fw::CodecData<'c>) {
    let mut mm = ml::MplsModule::new();
    if plt != 0 {
        let mut vp = Value::from_u64(u64::from(plt));
        vp.set_param(&ml::MPLS_PARAMS[1]);
        assert!(mm.set("payload_type", &mut vp));
    }
    let c = ml::MplsCodec::ctor(Some(&mm));
    let mut cd = fw::CodecData::new(Some(conf), ml::ETHERTYPE_MPLS_UNICAST);
    let mut d = ml::MplsHdr::default();
    let b = c.decode(&fw::RawData { data: bytes, len: bytes.len() as u32 }, &mut cd, &mut d, sink, bypass);
    (b, cd)
}

macro_rules! drain {
    ($evs:expr) => {
        *std::mem::take(&mut *$evs.borrow_mut())
    };
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 54 lines, ORDERED,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored;
//    fixtures copied EXACTLY from probe_dec.cc: the word faces 0x0000F00F
//    filler / 0x0000F30F lab15-bos-tc2-ttl15 / 0x000001FF lab0 /
//    0x000010FF+0x000011FF lab1 / 0x000021FF lab2 / 0x000030FF lab3, the
//    payload nibbles 0x41/0x61/0xFF/0x11). THE config-threading rides the
//    REAL mod->set ladder + ctor(Some(&m)) (:347-:354).
// ==========================================================================
#[test]
fn mpls_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 54, "vectors.txt must hold the full 54-line DEC ladder");

    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };
    // the queue_event witness seam: `EV %u %u` (GID_DECODE 116, carried
    // stubs_18d face — queue_event prints, NEVER re-walked).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };

    let conf = SnortConfig::default();
    // the tun mask mirror (probe :72/:212/:216): mask 0 -> bypass TRUE
    // (invisible on the earlier arms; M16/M17 print the face).
    let mut bypass0 = tun_witness(0u16); // the NSDMI tunnel_mask=0 ground face
    let mut bypass80 = tun_witness(0x80u16); // TUNNEL_MPLS armed

    // the probe's codec face: cc2 = a->ctor(nullptr) (DEFAULT cfg: depth
    // -1, plt AUTO).
    let cc2 = ml::MplsCodec::ctor(None); // :354 `new MplsCodec()` face

    // ---- M1 short-pkt wall :169-:172 -> EV 170 + false; lyr NEVER set ----
    {
        let (b, c, _) = probe_run(&cc2, &[0u8; 4], 3, &conf, &mut sink, &mut bypass0);
        push(format!("M1 len3 -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M2 one word 0x0000F30F: SOFT 175 + BoS print (t = the RAW 3-bit
    // tc face 2) + :191 set 512 + auto nibble 0x41 -> 2048 ----
    {
        let (b, c, d) = probe_run(&cc2, &[0x00, 0x00, 0xF3, 0x0F, 0x41, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!(
            "M2 one15 -> {} lyr={} next={} pb={} bo={} lab={} t={} ttl={}",
            b as i32, c.lyr_len, c.next_prot_id, c.proto_bits, d.bos, d.label, d.tc, d.ttl
        ));
    }
    // ---- M3/M4 label0-auto: :286 SHORT-CIRCUITS (plt 0) SILENT; :211
    // label0 -> 2048 overrides the 0x11/0x61 nibbles (label-first pin) ----
    {
        let (b, c, _) = probe_run(&cc2, &[0x00, 0x00, 0x01, 0xFF, 0x11, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M3 lab0-auto -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    {
        let (b, c, _) = probe_run(&cc2, &[0x00, 0x00, 0x01, 0xFF, 0x61, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M4 lab0-n6 -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M5 label1 MID-stack SILENT, entry2 SOFT 175, payload 0xFF ->
    // default 25944 ----
    {
        let (b, c, _) = probe_run(&cc2, &[0x00, 0x00, 0x10, 0xFF, 0x00, 0x00, 0xF3, 0x0F, 0xFF, 0x00, 0x00, 0x00], 12, &conf, &mut sink, &mut bypass0);
        push(format!("M5 lab1-mid -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M6 label1 AT BoS -> EV 172 FATAL (NO BoS print, pb 0) ----
    {
        let (b, c, _) = probe_run(&cc2, &[0x00, 0x00, 0x11, 0xFF], 4, &conf, &mut sink, &mut bypass0);
        push(format!("M6 lab1-bos -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M7 label2-auto SILENT (:302 gate, plt 0) + :213 -> 34525 ----
    {
        let (b, c, _) = probe_run(&cc2, &[0x00, 0x00, 0x21, 0xFF, 0x41, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M7 lab2-auto -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M8 label3 at ENTRY 8: 175 x7 THEN 174 (:308) + false BEFORE any
    // BoS capture — mplsHdr lab STAYS 0, pb STAYS 0 (:181-before-:186) ----
    {
        let bytes = [
            0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F,
            0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0x30, 0xFF,
        ];
        let (b, c, d) = probe_run(&cc2, &bytes, 32, &conf, &mut sink, &mut bypass0);
        push(format!("M8 lab3-e8 -> {} lyr={} next={} pb={} lab={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits, d.label));
    }
    // ---- config-thread arm (probe_dec.cc:139-:145): REAL mod->set ladder
    // (Values bound to MPLS_PARAMS[0]/[1] — the :91-:99 is()-binding face)
    // + ctor(Some(&m)) get_data() thread: depth 4 + plt ETH(idx 1). ----
    let mut m = ml::MplsModule::new();
    {
        let mut vd = Value::from_i64(4);
        vd.set_param(&ml::MPLS_PARAMS[0]); // pms+0 binding (the is() face)
        assert!(m.set("max_stack_depth", &mut vd));
        let mut vp = Value::from_u64(1);
        vp.set_param(&ml::MPLS_PARAMS[1]); // pms+1 (eth idx 1 — :41 alignment)
        assert!(m.set("payload_type", &mut vp));
    }
    let cd2 = ml::MplsCodec::ctor(Some(&m)); // the CONFIG-CARRYING ctor face

    // ---- M9 five-entry 15-stack on DEFAULT cc2: the -1 sentinel NEVER
    // arms :196 -> 175 x5, PASSES, lyr 20, nibble 0x41 -> 2048 ----
    {
        let bytes = [
            0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F,
            0x00, 0x00, 0xF3, 0x0F, 0x41, 0x00, 0x00, 0x00,
        ];
        let (b, c, _) = probe_run(&cc2, &bytes, 24, &conf, &mut sink, &mut bypass0);
        push(format!("M9 five -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M10 depth 4 (cd2): 175 x5 THEN :198 176; the entry-5 CAPTURE
    // rode FIRST (lab=15 bo=1) THEN :200 `pb &= ~512` == the 512->0 TRUE
    // CLEAR; entry-6 bos word NEVER read, lyr NEVER set ----
    {
        let bytes = [
            0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F,
            0x00, 0x00, 0xF3, 0x0F, 0x11, 0x00, 0x00, 0x00,
        ];
        let (b, c, d) = probe_run(&cd2, &bytes, 24, &conf, &mut sink, &mut bypass0);
        push(format!(
            "M10 five-d4 -> {} lyr={} next={} pb={} lab={} bo={}",
            b as i32, c.lyr_len, c.next_prot_id, c.proto_bits, d.label, d.bos
        ));
    }
    // ---- M11 FOUR-entry bos-stack vs cfg 4: `4 > 4` FALSE PASSES (the
    // ladder boundary); forced ETH rides 25944 (the honest auto-nibble
    // COINCIDENCE face — DIVERGENCE pins ride M12/M13/M14) ----
    {
        let bytes = [
            0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF3, 0x0F,
            0x11, 0x00, 0x00, 0x00,
        ];
        let (b, c, _) = probe_run(&cd2, &bytes, 20, &conf, &mut sink, &mut bypass0);
        push(format!("M11 four-d4-eth -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M12 label15-bos + FORCED ip4 (idx 2): :215 -> 2048 where auto
    // nibble 0x11 says 25944 (forced-vs-auto pin) ----
    {
        let mut m4 = ml::MplsModule::new();
        let mut vp = Value::from_u64(2);
        vp.set_param(&ml::MPLS_PARAMS[1]);
        assert!(m4.set("payload_type", &mut vp));
        let ci = ml::MplsCodec::ctor(Some(&m4));
        let (b, c, _) = probe_run(&ci, &[0x00, 0x00, 0xF3, 0x0F, 0x11, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M12 lab15-ip4 -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M13 label0-bos + FORCED eth: :286 `plt && plt!=IPV4` TRUE -> EV
    // 171 THEN :211 label0 rides FIRST -> 2048 (forced eth NEVER rides) ----
    {
        let mut m5 = ml::MplsModule::new();
        let mut vp = Value::from_u64(1);
        vp.set_param(&ml::MPLS_PARAMS[1]);
        assert!(m5.set("payload_type", &mut vp));
        let ce = ml::MplsCodec::ctor(Some(&m5));
        let (b, c, _) = probe_run(&ce, &[0x00, 0x00, 0x01, 0xFF, 0x11, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M13 lab0-eth -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M14 label0-bos + FORCED ip6: the gate reads IPV4 ONLY -> 171
    // AGAIN + :211 -> 2048 OVER the forced :217 34525 ----
    {
        let mut m6 = ml::MplsModule::new();
        let mut vp = Value::from_u64(3);
        vp.set_param(&ml::MPLS_PARAMS[1]);
        assert!(m6.set("payload_type", &mut vp));
        let c6 = ml::MplsCodec::ctor(Some(&m6));
        let (b, c, _) = probe_run(&c6, &[0x00, 0x00, 0x01, 0xFF, 0x11, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M14 lab0-ip6 -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- M15 DRAINED walk: two non-final 15s consume ALL 8 bytes ->
    // stack_len 0 -> WHILE RE-ENTERS -> :169 EV 170 (173/176 NEVER; lab 0) ----
    {
        let (b, c, d) = probe_run(&cc2, &[0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M15 drain -> {} lyr={} next={} pb={} lab={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits, d.label));
    }
    // ---- M16/M17 bypass-hook mask pair :205-:206 (TUNNEL_MPLS 0x80):
    // mask 0x80 -> bypass=0; mask 0 -> bypass=1 + bo=1 (pb 512 SET face,
    // NEVER cleared outside the depth arm) ----
    {
        let (b, c, _) = probe_run(&cc2, &[0x00, 0x00, 0x01, 0xFF, 0x11, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass80);
        push(format!("M16 mask80 -> {} lyr={} next={} bypass={}", b as i32, c.lyr_len, c.next_prot_id, c.tunnel_bypass as i32));
    }
    {
        let (b, c, d) = probe_run(&cc2, &[0x00, 0x00, 0x01, 0xFF, 0x11, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!(
            "M17 mask00 -> {} lyr={} next={} pb={} bypass={} bo={}",
            b as i32, c.lyr_len, c.next_prot_id, c.proto_bits, c.tunnel_bypass as i32, d.bos
        ));
    }
    // ---- M18 label2-bos + FORCED eth (eth != IPV6 -> :302 TRUE): EV 173
    // the ONLY 173 arm (config-forced census) + :213 -> 34525 ----
    {
        let mut m7 = ml::MplsModule::new();
        let mut vp = Value::from_u64(1);
        vp.set_param(&ml::MPLS_PARAMS[1]);
        assert!(m7.set("payload_type", &mut vp));
        let c7 = ml::MplsCodec::ctor(Some(&m7));
        let (b, c, _) = probe_run(&c7, &[0x00, 0x00, 0x21, 0xFF, 0x41, 0x00, 0x00, 0x00], 8, &conf, &mut sink, &mut bypass0);
        push(format!("M18 lab2-eth -> {} lyr={} next={} pb={}", b as i32, c.lyr_len, c.next_prot_id, c.proto_bits));
    }
    // ---- encode :246-:272 VECTORIZED on the mirror face: pflow nullptr ->
    // the `pflow_layer: None` seam arm (:251 true, :255 FALSE -> the
    // :249-:250 raw defaults); zero-size Buffer -> allocate(4) FALSE :264;
    // ok face = the memcpy_s :267 STOCK-#else-shim copy + the :268/:269
    // NOT_SET pair. ----
    let lab = [0x00u8, 0x00, 0xF3, 0x0F]; // probe's lab[4]
    {
        let mut one = [0u8; 1]; // the `uint8_t t=0` face (Buffer size 0)
        let mut b0 = fw::Buffer::new(&mut one, 0);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::PROTO_NOT_SET, 0, 0);
        let e0 = cc2.encode(&lab, 4, &mut enc, &mut b0, None); // bool var FIRST (R6)
        push(format!("ENC b0 -> {}", e0 as i32));
    }
    {
        let mut store = [0u8; 64];
        let mut b1 = fw::Buffer::new(&mut store, 32); // Buffer(q,32) face
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::PROTO_NOT_SET, 0, 0);
        let e1 = cc2.encode(&lab, 4, &mut enc, &mut b1, None);
        // the C format string HARDCODES `bytes 0 0 243 15` (probe_dec.cc
        // :249); the Rust driver prints the REAL copied window DECIMAL-
        // WISE — the identical line ONLY if the shim copy landed, i.e. a
        // STRICTER pin than the C print (the 4 label bytes 00 00 F3 0F).
        let out4 = b1.data().expect("allocate(4) just succeeded");
        assert_eq!(out4.len(), 4);
        push(format!(
            "ENC ok -> {} bytes {} {} {} {} netype {} npro {}",
            e1 as i32,
            out4[0], out4[1], out4[2], out4[3],
            enc.next_ethertype, enc.next_proto
        ));
    }

    let got = out.borrow();
    assert_eq!(got.len(), 54, "replay transcript length must equal the pinned face");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 17 lines (probe.cc over the ONE
//    TRUE-NAME table). EVERYTHING positional: the GETIDS block rides the
//    DETERMINISTIC std::vector emplace x3 (probe.cc:13-17 ORDER-PINNS it —
//    the vlan unordered-SET exception does NOT apply HERE).
// ==========================================================================
#[test]
fn mpls_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 17, "vectors_faceA.txt must hold the full 17-line walk");

    let mut got: Vec<String> = Vec::new();

    // table walk: LOAD mpls + LOADS 1 (ONE single-feed table :385/:388).
    for rec in ml::CD_MPLS.iter() {
        got.push(format!("LOAD {}", rec.name));
    }
    got.push(format!("LOADS {}", ml::CD_MPLS.len()));

    // API/HELP x1 (the :34/:35 CORRECTED macro faces — the docs ':33/:34'
    // citation is disk-dead, harness §1 re-sed).
    let a = ml::CD_MPLS[0];
    got.push(format!("API mpls type={} size={} ver={} name={}", a.ptype, a.size, a.api_version, a.name));
    got.push(format!("HELP mpls {}", a.help));
    // mod arms REAL (:341/:344 -> :371/:372) — the 1/1 face.
    got.push(format!("mpls mod_ctor={} mod_dtor={}", a.mod_ctor as u8, a.mod_dtor as u8));
    // CodecApi ctor/dtor SET (:378/:379 — the config-carrying ctor).
    got.push(format!("mpls ctor={} dtor={}", a.ctor as u8, a.dtor as u8));
    // ctor(nullptr) -> get_protocol_ids: the emplace x3 ORDER (cc :132-
    // :134), DECIMAL: 34887 / 34888 / 137 + the n face.
    {
        let c0 = ml::MplsCodec::ctor(None);
        let mut ids: Vec<u16> = Vec::new();
        c0.get_protocol_ids(&mut ids);
        for id in &ids {
            got.push(format!("GETIDS mpls {id}"));
        }
        got.push(format!("GETIDS_n {}", ids.len()));
    }
    // the REAL MplsModule face: NAME + RULES walk (mpls_rules :59-:69 via
    // the m->get_rules :54 census).
    let m = ml::MplsModule::new();
    got.push(format!("NAME mpls mod={} help={}", m.base.name, m.base.help));
    {
        let r = m.get_rules();
        let n = cmmod::rule_count(r);
        got.push(format!("RULES mpls n={} first={} last={}", n, r[0].sid, r[n - 1].sid));
    }
    // the PARAM inline raw-field walk (probe.cc:56-:68, the misc9
    // precedent): stop at the name-None / PT_MAX sentinel; PT_INT=4 /
    // PT_ENUM=11 ORDINALS via the landed Type enum (the same parameter.h
    // enum walk, python-derived in the harness); the range text from
    // MPLS_PARAM_RANGES (the landed Parameter omits the slot — the cited
    // deviation, value homes pinned in test 8).
    let mut np = 0usize;
    for (i, prm) in ml::MPLS_PARAMS.iter().take_while(|prm| prm.name.is_some() && prm.ptype != PtType::PtMax).enumerate() {
        let (range, deflt) = ml::MPLS_PARAM_RANGES[i];
        got.push(format!(
            "PARAM {} type={} range={} def={}",
            prm.name.unwrap(),
            prm.ptype as u32,
            range,
            deflt
        ));
        np += 1;
    }
    got.push(format!("PARAMS mpls n={np}"));
    // the set()/binding census (probe.cc:76-:83, the fmod V2-set prece-
    // dent): THREE Values ALL bound via set_param — v1->pms+0 (int 2),
    // v2->pms+1 (unum 2), v9->pms+0 (int 7 UNDER the bogus-name CALL —
    // still the max_stack_depth arm through its BINDING: is() is binding-
    // driven not arg-driven, the honest ground face); every arm TRUE.
    {
        let mut mm = ml::MplsModule::new();
        let mut v1 = Value::from_i64(2);
        v1.set_param(&ml::MPLS_PARAMS[0]);
        let mut v2 = Value::from_u64(2);
        v2.set_param(&ml::MPLS_PARAMS[1]);
        let mut v9 = Value::from_i64(7);
        v9.set_param(&ml::MPLS_PARAMS[0]);
        let s1 = u8::from(mm.set("max_stack_depth", &mut v1));
        let s2 = u8::from(mm.set("payload_type", &mut v2));
        let s3 = u8::from(mm.set("bogus_name", &mut v9));
        got.push(format!("SET mpls ret={s1}{s2}{s3}"));
        // config read-back (the get_data() feed the CTOR_M thread rode):
        assert_eq!((mm.config.stack_depth, mm.config.payload_type), (7, 2), "the set ladder read-back (:94/:96 + the binding arm)");
    }
    // the ctor(m) config-thread census face :347-:355: the C probe prints
    // `c1 ? 1 : 0` (non-null); the Rust ctor returns a VALUE — BOTH arms
    // (:349-:352 Some / :354 None) always yield a codec, so the ok=1 face
    // is compile-true HERE (the config READ-BACK asserts the thread; the
    // BEHAVIORAL half rides the DEC M10/M11 arms on cd2).
    {
        let c1 = ml::MplsCodec::ctor(Some(&m));
        let ok: u8 = u8::from(c1.config.stack_depth == -1 && m.config.stack_depth == -1);
        got.push(format!("CTOR_M mpls ok={ok}"));
    }

    assert_eq!(got.len(), 17, "FACE-A transcript length must equal the pinned face");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "faceA line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 3. TRUE-NAME triple tripwires — cd_mpls[] :385 == the FILE base (the 18n
//    equality-pin law: NO drift refusal needed HERE, the equality IS the
//    nm D-face pin). Ladder RESIDENT codec_api.rs (ground extern
//    codec_api.cc :61 + load :106) NEVER re-walked — THIS row TURNS it
//    loaded; the [&str; 34] census UNDISTURBED. THE sid-band NEVER-land
//    FLIP census: band grep-0 ACROSS ALL FOUR landed predecessor vectors
//    WHILE the OWN face runs 34 strong (censused in test 5).
// ==========================================================================
#[test]
fn mpls_true_name_tripwire() {
    const M_RS: &str = include_str!("../src/codecs/cd_mpls.rs");
    // the table const pins EXACTLY (single feed):
    assert!(
        M_RS.contains("pub const CD_MPLS: CodecTable = &[&MPLS_API];"),
        "the cd_mpls TRUE-NAME table const drifted (:385, feed :388)"
    );
    // the hidden-BUILDING_SO cite lines ride the source face (:382-:386):
    assert!(M_RS.contains("const BaseApi* cd_mpls[] =") || M_RS.contains("`const BaseApi* cd_mpls[] =`")); // :385 cite
    assert!(M_RS.contains("BUILDING_SO"), "the :382 split cite rides");
    // ZERO no_mangle (the src-wide landed pattern):
    assert!(!M_RS.contains("#[no_mangle]"), "the src-wide landed pattern: ZERO no_mangle");
    // the ground file cite rides the module header (the honesty face):
    assert!(M_RS.contains("cd_mpls.cc"), "the ground TU cite rides");
    // ladder RESIDENT ("cd_mpls" in the 34-name table) — NEVER re-walked:
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_mpls"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18o adds NO new externs"
    );
    // NAME macros (faceA name pins, the :34/:35 CORRECTION):
    assert_eq!(ml::CD_MPLS[0].name, "mpls"); // :34
    assert_eq!(ml::CD_MPLS[0].help, "support for multiprotocol label switching"); // :35
    // single feed (`&mpls_api.base` :388 — ONE entry, the LOADS 1 face):
    assert_eq!(ml::CD_MPLS.len(), 1);
    // THE sid-band NEVER-land census stays TRUE in ALL FOUR landed
    // predecessor vectors, EVEN AS the band fires at OWN face (the q4
    // flip NEVER leaks — build.sh's python face mirrored Rust-side):
    for face in [L4_DEC, L4_FA, L6_DEC, L6_FA, ESP_DEC, ESP_FA, M9_DEC, M9_FA] {
        for sid in 170u32..=176 {
            assert!(!face.contains(&format!("EV 116 {sid}")), "the {sid} band leaked into a LANDED predecessor vectors face");
        }
    }
    // the flip is POSITIVE at OWN face (the grep-1 arm of the same law):
    let own_band: Vec<&str> = VECTORS
        .lines()
        .filter(|l| (170u32..=176).any(|sid| *l == format!("EV 116 {sid}")))
        .collect();
    assert_eq!(own_band.len(), 34, "the OWN-face sid band must FIRE POSITIVE (34 EV lines)");
}

// ==========================================================================
// 4. THE record census: 112/1900547/PT_CODEC + ctor/dtor SET + g/t
//    nullptr x4; mod arms MEASURED REAL (the `mpls mod_ctor=1
//    mod_dtor=1` faceA pin — point-site allow, the ext/small4/misc3/
//    erspan/link6/link4 lineage precedent). THE RuleMap census: 7 data
//    rows + terminator, msgs byte-exact off the ground strings. THE sids
//    SEVEN DISTINCT RESIDENT {170..176} codec_module.rs :113-:119 (h :100-
//    :106) — ZERO new consts; the source-side re-declaration refusal
//    tripwired.
// ==========================================================================
#[test]
fn mpls_record_census() {
    let a = &ml::MPLS_API;
    assert_eq!(a.ptype, fw::PT_CODEC); // :363
    assert_eq!(a.size, 112);            // sizeof(CodecApi), faceA size pin
    assert_eq!(a.api_version, 1900547); // faceA ver pin
    assert_eq!(a.version, 0);
    assert_eq!(a.features, fw::PLUGIN_SO_RELOAD);
    assert_eq!(a.options, fw::API_OPTIONS);
    assert!(!a.pinit);
    assert!(!a.pterm);
    assert!(!a.tinit);
    assert!(!a.tterm);
    assert!(a.ctor);
    assert!(a.dtor);
    // THE mod-arms MEASURED REAL (faceA :5 — the :341/:344 pair; compile-
    // time record consts, the lineage's point-site allow precedent):
    #[allow(clippy::assertions_on_constants)] // pinned record-const face (lineage precedent, point-site)
    {
        assert!(ml::MPLS_API.mod_ctor && ml::MPLS_API.mod_dtor, "mpls arms REAL (:341/:344 -> :371/:372)");
    }

    // the module face: the REAL MplsModule (mod arms mirror):
    let m = ml::MplsModule::new();
    assert_eq!(m.base.name, "mpls");
    assert_eq!(m.base.help, ml::CD_MPLS_HELP);
    assert_eq!(cmmod::rule_count(m.get_rules()), 7); // :61-:67 rows + :68 term

    // the params face (mpls_params :48-:57): TWO data rows + PT_MAX term:
    assert_eq!(ml::MPLS_PARAMS.len(), 3);
    assert_eq!(ml::MPLS_PARAMS[0].name, Some("max_stack_depth")); // :50
    assert_eq!(ml::MPLS_PARAMS[0].ptype, PtType::PtInt);           // :50 (ordinal 4, faceA type=4)
    assert_eq!(ml::MPLS_PARAMS[0].deflt, Some("-1"));              // :50 THE -1 SENTINEL (:196 gate-off)
    assert_eq!(ml::MPLS_PARAMS[1].name, Some("payload_type"));    // :53
    assert_eq!(ml::MPLS_PARAMS[1].ptype, PtType::PtEnum);          // :53 (ordinal 11, faceA type=11)
    assert_eq!(ml::MPLS_PARAMS[1].deflt, Some("auto"));            // :53
    assert_eq!(ml::MPLS_PARAMS[2].name, None);                     // :56 nullptr row
    assert_eq!(ml::MPLS_PARAMS[2].ptype, PtType::PtMax);           // :56 sentinel

    // RuleMap census + byte-exact msgs (:61-:67, straight off the ground):
    let want_msgs: [(u32, &str); 7] = [
        (170, "bad MPLS frame"),
        (171, "MPLS label 0 appears in bottom header when not decoding as ip4"),
        (172, "MPLS label 1 appears in bottom header"),
        (173, "MPLS label 2 appears in bottom header when not decoding as ip6"),
        (174, "MPLS label 3 appears in header"),
        (175, "MPLS label 4, 5,.. or 15 appears in header"),
        (176, "too many MPLS headers"),
    ];
    assert_eq!(ml::MPLS_RULES.len(), 8);
    for (i, (sid, msg)) in want_msgs.iter().enumerate() {
        assert_eq!(ml::MPLS_RULES[i].sid, *sid);
        assert_eq!(ml::MPLS_RULES[i].msg, Some(*msg));
    }
    assert_eq!(ml::MPLS_RULES[7].sid, 0);
    assert_eq!(ml::MPLS_RULES[7].msg, None);

    // sids SEVEN RESIDENT (ZERO new consts; the h-line cites ride):
    assert_eq!(cmmod::CodecSid::DECODE_BAD_MPLS as u32, 170);             // :113, h:100
    assert_eq!(cmmod::CodecSid::DECODE_BAD_MPLS_LABEL0 as u32, 171);      // :114, h:101
    assert_eq!(cmmod::CodecSid::DECODE_BAD_MPLS_LABEL1 as u32, 172);      // :115, h:102
    assert_eq!(cmmod::CodecSid::DECODE_BAD_MPLS_LABEL2 as u32, 173);      // :116, h:103
    assert_eq!(cmmod::CodecSid::DECODE_BAD_MPLS_LABEL3 as u32, 174);      // :117, h:104
    assert_eq!(cmmod::CodecSid::DECODE_MPLS_RESERVED_LABEL as u32, 175);  // :118, h:105
    assert_eq!(cmmod::CodecSid::DECODE_MPLS_LABEL_STACK as u32, 176);     // :119, h:106
    // the RESIDENCE tripwire: the row file NEVER re-declares a sid const
    // (every RuleMap row + every codec_event rides the CodecSid landing):
    const M_RS: &str = include_str!("../src/codecs/cd_mpls.rs");
    for tok in ["DECODE_BAD_MPLS = 170", "pub const DECODE_", "const DECODE_BAD_MPLS"] {
        assert!(!M_RS.contains(tok), "a sid const was RE-DECLARED in cd_mpls.rs: {tok}");
    }

    // HELP/NAME faces (faceA :4/:11 pins):
    assert_eq!(ml::MPLS_API.help, "support for multiprotocol label switching");
    assert_eq!(ml::MPLS_API.name, "mpls");
}

// ==========================================================================
// 5. VECTORS-face census: EV = 34 lines / the measured per-sid counts
//    {170x2, 171x2, 172x1, 173x1, 174x1, 175x26, 176x1} (the python
//    census face re-derived HERE); GID 116 everywhere; all-decimal hygiene
//    BOTH faces; THE seed-DRAFT decimal DRIFT tripwires (34781/25946 NEVER
//    appear — the ground hex walk 34525/25944 owns the vectors, §11(c));
//    the decode-arm census EXACTLY 18 (NOT the drafted 19 — §11(e)); the
//    bypass DUAL-FACE positional pins; the M10 512->0 TRUE-CLEAR order pin;
//    the M15 drain pin; the faceA census lines; ZERO tunnel tokens on
//    FACE-A (the hook face rides DEC ONLY).
// ==========================================================================
#[test]
fn mpls_vector_census() {
    // EV census: EXACTLY-34 lines, the measured per-sid counts:
    let evs: Vec<&str> = VECTORS.lines().filter(|l| l.starts_with("EV ")).collect();
    assert_eq!(evs.len(), 34, "the ground codec_event census 34 (the PLAN §11 flip face)");
    let want_counts: [(u32, usize); 7] = [(170, 2), (171, 2), (172, 1), (173, 1), (174, 1), (175, 26), (176, 1)];
    let mut sum = 0usize;
    for (sid, n) in want_counts {
        let got = VECTORS.lines().filter(|l| *l == format!("EV 116 {sid}")).count();
        assert_eq!(got, n, "EV {sid} count (the per-arm census)");
        sum += got;
    }
    assert_eq!(sum, 34);
    // the band {170..176} closes (no off-band sid anywhere — the walk
    // re-derivation):
    assert!(!VECTORS.contains("EV 116 177"), "an off-band sid crept into the vectors");
    assert!(evs.iter().all(|l| l.starts_with("EV 116 "))); // GID_DECODE (codec_module.h :38)

    // all-decimal hygiene (harness grep-0 face, BOTH faces):
    assert!(!VECTORS.contains("0x"), "DEC face carries a hex literal");
    assert!(!VECTORS_FACE_A.contains("0x"), "FACE-A carries a hex literal");
    // THE DECIMAL-GROUND DRIFT tripwires (§11(c): the seed-draft head-math
    // said ip6=34781 briding=25946; the ground hex walk says 34525/25944 —
    // the pins follow the GREP, never the draft):
    for drift in ["34781", "25946"] {
        assert!(!VECTORS.contains(drift), "the drifted seed decimal {drift} crept into vectors");
    }
    assert!(VECTORS.contains("next=34525"), "the ground ip6 34525 face MUST ride");
    assert!(VECTORS.contains("next=25944"), "the ground bridging 25944 face MUST ride");

    // THE decode-arm census EXACTLY 18 (NOT 19 — §11(e) R6 face): the
    // M-printed decode lines == M1..M18.
    let m_arms: Vec<&str> = VECTORS.lines().filter(|l| l.starts_with('M') && l.contains(" -> ")).collect();
    assert_eq!(m_arms.len(), 18, "the decode-arm census is 18 (M1..M18), NEVER 19");
    assert_eq!(VECTORS.lines().filter(|l| l.starts_with("ENC ")).count(), 2, "the two encode arms");

    let lines: Vec<&str> = VECTORS.lines().collect();
    // the bypass DUAL-FACE positional pair :205-:206 (M16 prints NO pb —
    // bypass 0; M17 SAME bytes pb=512 bypass=1 + bo):
    assert_eq!(lines[48], "M16 mask80 -> 1 lyr=4 next=2048 bypass=0", "the hook mask-armed FALSE face (:205 rides, TUNNEL_MPLS 0x80)");
    assert_eq!(lines[49], "M17 mask00 -> 1 lyr=4 next=2048 pb=512 bypass=1 bo=1", "the hook un-armed TRUE face (the NSDMI mask-0 ground)");
    // THE M10 512->0 TRUE-CLEAR order pin: :191 SET rode at entry 5 (the
    // capture print proves lab/bo) THEN :200 CLEARED it before the print
    // (the §11(g) FIVE-entry re-design — the draft six-entry face never
    // SET pb, so its 'clear' was vacuous):
    assert_eq!(lines[30], "EV 116 175", "M10 entry-5 SOFT 175 (the 5th) INSIDE the walk, before the gate");
    assert_eq!(lines[31], "EV 116 176", "M10 depth gate :198 AFTER the capture");
    assert_eq!(lines[32], "M10 five-d4 -> 0 lyr=0 next=34887 pb=0 lab=15 bo=1", "the :200 512->0 TRUE CLEAR + the :186 capture BEFORE it + lyr NEVER set (:208 unreached)");
    // the M15 drain face (the face a tail-counting rule MISSES):
    assert_eq!(lines[44], "EV 116 175", "M15 filler 1");
    assert_eq!(lines[45], "EV 116 175", "M15 filler 2");
    assert_eq!(lines[46], "EV 116 170", "the :169-at-drain re-fire face (stack_len hits 0)");
    assert_eq!(lines[47], "M15 drain -> 0 lyr=0 next=34887 pb=0 lab=0", "no bos captured, lab STAYS value-init 0");
    // the M8 eval-order pin (175x7 THEN 174, capture NEVER ran):
    assert_eq!(lines[18], "EV 116 174", "M8 :308 unconditional 174 at entry 8");
    assert_eq!(lines[19], "M8 lab3-e8 -> 0 lyr=0 next=34887 pb=0 lab=0", "the :181-before-:186 receipt (pb NEVER set, lab 0)");
    // the -1 sentinel pin (the config-threading face): the DEFAULT-cfg
    // five-stack PASSES:
    assert_eq!(lines[25], "M9 five -> 1 lyr=20 next=2048 pb=512", "the -1 deflt NEVER arms :196 on the default cfg");

    // GETIDS emplace-x3 DECIMAL pins (faceA, ORDER-PINNED cc :132-:134):
    assert!(VECTORS_FACE_A.contains("GETIDS mpls 34887")); // protocol_ids.h :153
    assert!(VECTORS_FACE_A.contains("GETIDS mpls 34888")); // :154
    assert!(VECTORS_FACE_A.contains("GETIDS mpls 137"));   // :114 (MPLS_IP, framework-resident)
    assert!(VECTORS_FACE_A.contains("GETIDS_n 3"));
    // the faceA census lines:
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOAD ")).count(), 1);
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOADS 1")).count(), 1);
    assert!(VECTORS_FACE_A.contains("SET mpls ret=111"), "the binding-driven SET face (the bogus-name arm STILL true via its pms+0 is() binding)");
    assert!(VECTORS_FACE_A.contains("CTOR_M mpls ok=1"), "the config-carrying ctor(m) census");
    assert!(VECTORS_FACE_A.contains("RULES mpls n=7 first=170 last=176")); // :59-:69 walk
    assert!(VECTORS_FACE_A.contains("PARAM max_stack_depth type=4 range=-1:255 def=-1")); // :50
    assert!(VECTORS_FACE_A.contains("PARAM payload_type type=11 range=auto | eth | ip4 | ip6 def=auto")); // :53
    assert!(VECTORS_FACE_A.contains("PARAMS mpls n=2"));
    assert!(VECTORS_FACE_A.contains("NAME mpls mod=mpls help=support for multiprotocol label switching")); // :34/:35 CORRECTION
    // the hook face rides DEC ONLY (probe.cc NEVER prints tunnel):
    assert!(!VECTORS_FACE_A.contains("tunnel") && !VECTORS_FACE_A.contains("bypass"), "the hook print crept into FACE-A (probe NEVER prints it)");
    assert!(VECTORS.contains("bypass=0") && VECTORS.contains("bypass=1"), "the dual bypass face lives HERE (:205-:206 arms)");
    // the encode face prints the shim-copied 4 label bytes + the NOT_SET pair:
    assert!(VECTORS.contains("ENC b0 -> 0"), "the allocate(4)-over-zero-size Buffer false face :264");
    assert!(VECTORS.contains("ENC ok -> 1 bytes 0 0 243 15 netype 0 npro 255"), "the memcpy_s :267 stock-shim copy + :268/:269 NOT_SET (protocol_ids.h :91/:122)");
}

// ==========================================================================
// 6. UNIT: the bit-layout ladder (decode_mpls_entry — the rfc5462 :139-
//    :149 faces) + the depth boundary (4/5 on cfg-4 + the -1 sentinel
//    NEVER firing) + THE M10 512->0 TRUE-CLEAR behavior twin (capture
//    BEFORE the gate) + THE reserved-gate matrix (label0/label2 auto-
//    SILENT vs the forced-plt 171/173 arms — the ip4/ip6 GATE-OFF mirror
//    too; label1-mid SILENT vs label1-bos FATAL; label3 unconditional
//    FATAL; label-15 SOFT CONTINUES; label >=16 SKIPS validate) + the
//    LABEL-FIRST ladder over BOTH forced arms + the first-nibble sweep +
//    the empty-payload :226-:227 false face + the bypass-only-on-completed-
//    walk twin.
// ==========================================================================
#[test]
fn up_mpls_ladder() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let cc2 = ml::MplsCodec::ctor(None); // DEFAULT: depth -1, plt AUTO(0)
    let mut bypass_off = |_p: u16| -> bool { false };

    // the bit-layout face (:151-:156): ttl low byte, bos = (w>>8)&1,
    // tc = (w>>8)&0x0E RAW UNnormalized, label = (w>>12)&0xFFFFF:
    assert_eq!(ml::decode_mpls_entry(0x0000_F30F), (15, 2, 1, 15)); // the ONE-word face (M2)
    assert_eq!(ml::decode_mpls_entry(0x0000_F00F), (15, 0, 0, 15)); // the NON-final filler (the S-bit byte-2 trap face)
    assert_eq!(ml::decode_mpls_entry(0x0000_30FF), (3, 0, 0, 255)); // the label3 entry (M8)
    assert_eq!(ml::decode_mpls_entry(0xFFFF_FFFF), (0x000F_FFFF, 0x0E, 1, 0xFF)); // every field at max
    assert_eq!(ml::decode_mpls_entry(0x000F_0FFF), (240, 14, 1, 255)); // the 20-bit label face (>=16, validate SKIPPED)

    // depth boundary on cfg 4 (the ctor(Some) thread): FOUR bos-stack
    // PASSES (`4 > 4` FALSE — the M11 boundary); FIVE fires :196 AFTER
    // the entry-5 capture+set (the behavior twin of the vectors' M10).
    {
        let mut m = ml::MplsModule::new();
        let mut vd = Value::from_i64(4);
        vd.set_param(&ml::MPLS_PARAMS[0]);
        assert!(m.set("max_stack_depth", &mut vd));
        let cd2 = ml::MplsCodec::ctor(Some(&m));
        assert_eq!(cd2.config.stack_depth, 4, "the ctor(m) config thread (:352 get_data())");

        // three F00F + F30F bos -> TRUE, NO 176, pb 512:
        let four = [0x00u8, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF3, 0x0F, 0x11, 0x00, 0x00, 0x00];
        let (b, cd, d) = probe_run(&cd2, &four, 20, &conf, &mut sink, &mut bypass_off);
        assert!(b, "4 > 4 FALSE: the ladder boundary PASSES (:196)");
        assert_eq!(drain!(evs), vec![(116, 175); 4]);
        assert_eq!((cd.lyr_len, cd.proto_bits), (16, 512));
        assert_eq!((d.label, d.bos), (15, 1));

        // five: capture rode FIRST at entry 5 THEN :200 CLEARED pb -> pb 0
        // with lab/bo kept (the 512->0 TRUE-CLEAR proof, NEVER vacuous):
        let five = [0x00u8, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF3, 0x0F, 0x11, 0x00, 0x00, 0x00];
        let (b, cd, d) = probe_run(&cd2, &five, 24, &conf, &mut sink, &mut bypass_off);
        assert!(!b, "++depth 5 > 4 -> :201 false");
        assert_eq!(drain!(evs), vec![(116, 175), (116, 175), (116, 175), (116, 175), (116, 175), (116, 176)]);
        assert_eq!(
            (cd.lyr_len, cd.proto_bits),
            (0, 0),
            "lyr NEVER set (:208) + THE :200 512->0 TRUE CLEAR (:191 RODE first, see lab/bo)"
        );
        assert_eq!((d.label, d.bos), (15, 1), "the :186-:189 capture rode BEFORE the gate");
    }
    // the -1 sentinel NEVER arms (:196 LHS first — 20 entries on the
    // DEFAULT cfg PASSES with NO 176 anywhere):
    {
        let mut big: Vec<u8> = vec![];
        for _ in 0..19 {
            big.extend_from_slice(&[0x00, 0x00, 0xF0, 0x0F]);
        }
        big.extend_from_slice(&[0x00, 0x00, 0xF3, 0x0F]);
        big.extend_from_slice(&[0x41, 0, 0, 0]);
        let len = big.len() as u32;
        let (b, cd, _) = probe_run(&cc2, &big, len, &conf, &mut sink, &mut bypass_off);
        assert!(b, "stack_depth -1: :196 NEVER arms (the deflt \"-1\" face :50)");
        assert_eq!(drain!(evs), vec![(116, 175); 20]);
        assert_eq!((cd.lyr_len, cd.proto_bits), (80, 512));
    }
    // THE reserved-label matrix (the config census — 171/173 are CONFIG-
    // FORCED faces; the gate ODDITIES pinned: label0 reads IPV4 — so the
    // ip6 force trips TOO and the ip4 force rides OFF; label2 reads IPV6
    // — mirror image):
    {
        // label0-bos:
        let lab0 = [0x00u8, 0x00, 0x01, 0xFF, 0x11, 0x00, 0x00, 0x00];
        for (plt, ev, tag) in [(0u8, vec![], "auto"), (1, vec![(116, 171)], "eth"), (2, vec![], "ip4-gate-off"), (3, vec![(116, 171)], "ip6-trips-too")] {
            let (b, cd) = cfg_run(&lab0, plt, &conf, &mut sink, &mut bypass_off);
            assert!(b, "lab0 {tag}: SOFT 171 NEVER returns false (:288 break)");
            assert_eq!(drain!(evs), ev, "lab0 {tag} EV face");
            assert_eq!(cd.next_prot_id, 2048, "lab0 {tag}: :211 rides FIRST over EVERY forced arm");
        }
        // label1: MID-stack SILENT continues (:292 bos FALSE — NO event at
        // ALL); AT bos FATAL:
        let lab1mid = [0x00u8, 0x00, 0x10, 0xFF, 0x00, 0x00, 0xF3, 0x0F, 0x11, 0x00, 0x00, 0x00];
        let (b, _) = cfg_run(&lab1mid, 0, &conf, &mut sink, &mut bypass_off);
        assert!(b, "mid-stack label1 rides SILENT (:292 FALSE)");
        assert_eq!(drain!(evs), vec![(116, 175)]);
        let lab1bos = [0x00u8, 0x00, 0x11, 0xFF];
        let (b, cd) = cfg_run(&lab1bos, 0, &conf, &mut sink, &mut bypass_off);
        assert!(!b, "label1 AT bos -> :295 FATAL");
        assert_eq!(drain!(evs), vec![(116, 172)]);
        assert_eq!((cd.lyr_len, cd.proto_bits, cd.next_prot_id), (0, 0, 34887), "the FATAL arm touches NOTHING");
        // label2-bos: AUTO SILENT / eth + ip4 fire 173 / ip6 GATE-OFF:
        let lab2 = [0x00u8, 0x00, 0x21, 0xFF, 0x41, 0x00, 0x00, 0x00];
        for (plt, ev, tag) in [(0u8, vec![], "auto"), (1, vec![(116, 173)], "eth"), (2, vec![(116, 173)], "ip4"), (3, vec![], "ip6-gate-off")] {
            let (b, cd) = cfg_run(&lab2, plt, &conf, &mut sink, &mut bypass_off);
            assert!(b, "lab2 {tag}: SOFT");
            assert_eq!(drain!(evs), ev, "lab2 {tag} EV face");
            assert_eq!(cd.next_prot_id, 34525, "lab2 {tag}: :213 rides FIRST");
        }
        // label3: UNCONDITIONAL FATAL on EVERY config (:308-:309):
        let lab3 = [0x00u8, 0x00, 0x30, 0xFF, 0x11, 0x00, 0x00, 0x00];
        for plt in [0u8, 1, 2, 3] {
            let (b, _) = cfg_run(&lab3, plt, &conf, &mut sink, &mut bypass_off);
            assert!(!b, "lab3 config {plt} FATAL either way");
            assert_eq!(drain!(evs), vec![(116, 174)]);
        }
        // label-15: <16 SOFT 175 CONTINUES (the :313 arm, 26 fires of
        // census); label-240 (0x000F0FFF): >=16 -> the :181 range gate
        // SKIPS validate ENTIRELY — NO event, bos still captured:
        let over = [0x00u8, 0x0F, 0x0F, 0xFF, 0x11, 0x00, 0x00, 0x00];
        let (b, cd) = cfg_run(&over, 0, &conf, &mut sink, &mut bypass_off);
        assert!(b, "label 240 SKIPS the :181 validate (NUM_RESERVED_LABELS gate)");
        assert_eq!(drain!(evs), vec![], "the range gate NEVER reaches the switch");
        assert_eq!((cd.lyr_len, cd.next_prot_id), (4, 25944), "label>=16: bos-yes, auto nibble 0x11 -> :238 default");
    }
    // the FIRST-NIBBLE sweep (:228-:240) on label-15-bos auto cfg:
    {
        for (pl, want) in [(0x41u8, 2048u16), (0x61, 34525), (0xFF, 25944), (0x11, 25944)] {
            let w = [0x00u8, 0x00, 0xF3, 0x0F, pl, 0x00, 0x00, 0x00];
            let (b, cd, _) = probe_run(&cc2, &w, 8, &conf, &mut sink, &mut bypass_off);
            assert!(b);
            assert_eq!(drain!(evs), vec![(116, 175)]);
            assert_eq!(cd.next_prot_id, want, "auto nibble 0x{pl:02X}");
        }
    }
    // the empty-payload face :226-:227: label-15 bos with NO payload ->
    // lyr_len == raw.len -> the auto arm returns FALSE (next NEVER
    // written — the honest no-ladder-arm face); label0-SAME-LENGTH rides
    // :211 TRUE (the guard rides the AUTO arm ONLY):
    {
        let w = [0x00u8, 0x00, 0xF3, 0x0F];
        let (b, cd, _) = probe_run(&cc2, &w, 4, &conf, &mut sink, &mut bypass_off);
        assert!(!b, "the :227 label-only-stack false face (auto)");
        assert_eq!(drain!(evs), vec![(116, 175)]);
        assert_eq!(cd.next_prot_id, 34887, "NO ladder arm ran — init_prot stays");
        let w0 = [0x00u8, 0x00, 0x01, 0xFF]; // label0 bos, no payload
        let (b, cd, _) = probe_run(&cc2, &w0, 4, &conf, &mut sink, &mut bypass_off);
        assert!(b, ":211 label0 rides BEFORE the auto guard (:226)");
        assert_eq!(drain!(evs), vec![]);
        assert_eq!(cd.next_prot_id, 2048);
    }
    // the bypass closure twin: :206 arms ONLY on a COMPLETED walk (the
    // FATAL M6 face NEVER reaches :205 even with the hook TRUE):
    {
        let mut bypass_on = tun_witness(0u16);
        let (b, cd, _) = probe_run(&cc2, &[0x00u8, 0x00, 0x11, 0xFF], 4, &conf, &mut sink, &mut bypass_on);
        assert!(!b && !cd.tunnel_bypass, "a FATAL walk NEVER reaches :205 (the :295 return rides first)");
    }
}

// ==========================================================================
// 7. UNIT: the module-face — the begin-reset (:87), the binding-driven set
//    arms (:94/:96), the silent-arm TRUE (:98, the bogus-name face), the
//    ctor(None)/ctor(Some) pairing, the get_protocol_ids emplace ORDER,
//    the encode family (the allocate-fail face, the shim-copy + NOT_SET
//    pair, the MplsLayer seam re-point :255-:258, the length-0 arm), and
//    the log seam (cited-never-called, ported-by-reading, unit-mirrored).
// ==========================================================================
#[test]
fn up_mpls_module_encode_log() {
    // the begin-reset face :85-:89:
    {
        let mut m = ml::MplsModule::new();
        assert_eq!(m.config.stack_depth, -1, "the NSDMI/-1 deflt face (:73/:50)");
        let mut vd = Value::from_i64(9);
        vd.set_param(&ml::MPLS_PARAMS[0]);
        assert!(m.set("max_stack_depth", &mut vd));
        assert_eq!(m.config.stack_depth, 9, "the :94 get_int16 arm");
        let mut vp = Value::from_u64(3);
        vp.set_param(&ml::MPLS_PARAMS[1]);
        assert!(m.set("payload_type", &mut vp));
        assert_eq!(m.config.payload_type, 3, "the :96 get_uint8 arm");
        let mut v9 = Value::from_i64(7);
        v9.set_param(&ml::MPLS_PARAMS[0]);
        assert!(m.set("bogus_name", &mut v9), ":98 TRUE even off-name (the binding-driven is() face)");
        assert_eq!(m.config.stack_depth, 7, "the bogus-name call hit max_stack_depth via its pms+0 BINDING");
        assert!(m.begin("", 0));
        assert_eq!((m.config.stack_depth, m.config.payload_type), (-1, 0), "config = {{ }} at begin (:87)");
    }
    // the ctor pairing faces: None -> the NSDMI default; Some -> the
    // get_data thread (the behavior rode the ladder unit above):
    {
        let cdef = ml::MplsCodec::ctor(None);
        assert_eq!((cdef.config.stack_depth, cdef.config.payload_type), (-1, 0), ":354 new MplsCodec()");
        let mut m = ml::MplsModule::new();
        let mut vd = Value::from_i64(2);
        vd.set_param(&ml::MPLS_PARAMS[0]);
        assert!(m.set("max_stack_depth", &mut vd));
        let cm = ml::MplsCodec::ctor(Some(&m));
        assert_eq!(cm.config.stack_depth, 2, ":351-:352 the config-carrying ctor");
    }
    // get_protocol_ids emplace ORDER (:132-:134 — the vector emplace x3,
    // NEVER a set — the vlan unordered-SET contrast NEVER applies):
    {
        let mut ids = Vec::new();
        ml::MplsCodec::ctor(None).get_protocol_ids(&mut ids);
        assert_eq!(ids, vec![34887, 34888, 137], "the vector emplace order (:132-:134)");
    }
    // the encode family (the vectors' two ENC arms BEHAVIOR twins):
    {
        let lab = [0x00u8, 0x00, 0xF3, 0x0F];
        // the allocate-fail arm (:264-:265, zero-size Buffer):
        let mut one = [0u8; 1];
        let mut b0 = fw::Buffer::new(&mut one, 0);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::PROTO_NOT_SET, 0, 0);
        enc.next_ethertype = 0x1234;
        enc.next_proto = 99;
        assert!(!ml::MplsCodec::ctor(None).encode(&lab, 4, &mut enc, &mut b0, None));
        assert_eq!((enc.next_ethertype, enc.next_proto), (0x1234, 99), "the FALSE arm NEVER reached :268/:269");
        // the None-mirror (harness witness) face: the RAW window rides +
        // the shim copy + the NOT_SET pair (the ENC ok line):
        let mut store = [0u8; 64];
        let mut b1 = fw::Buffer::new(&mut store, 32);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::PROTO_NOT_SET, 0, 0);
        enc.next_ethertype = 0x1234;
        enc.next_proto = 99;
        assert!(ml::MplsCodec::ctor(None).encode(&lab, 4, &mut enc, &mut b1, None));
        let out = b1.data().expect("allocate(4) just succeeded");
        assert_eq!(&out[..4], &lab[..4], ":267 memcpy_s via the STOCK safec.h #else shim == a PLAIN copy (HAVE_SAFEC grep-0; the C15 law)");
        assert_eq!(enc.next_ethertype, fw::protocol_id::ETHERTYPE_NOT_SET); // :268 (netype 0)
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET);         // :269 (npro 255)
        // the Some(layer) seam arm (the left-open face the harness
        // mirror NEVER rode — the ground :255-:258 re-point, unit-armed
        // HERE; the REAL provider stays queued, NEVER invented):
        let layer_bytes = [0xABu8, 0xCD, 0xEF, 0x01, 0x23];
        let layer = ml::MplsLayer { length: 4, start: &layer_bytes };
        let mut store = [0u8; 64];
        let mut b2 = fw::Buffer::new(&mut store, 32);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::PROTO_NOT_SET, 0, 0);
        assert!(ml::MplsCodec::ctor(None).encode(&lab, 8, &mut enc, &mut b2, Some(&layer)));
        let out = b2.data().expect("allocate(4) just succeeded");
        assert_eq!(&out[..4], &layer_bytes[..4], ":257-:258 the layer window RE-POINTS the copy (the layer length 4 beats raw_len 8)");
        // the layer-with-length-0 arm: :255 FALSE -> the raw defaults ride:
        let zero_layer = ml::MplsLayer { length: 0, start: &layer_bytes };
        let mut store = [0u8; 64];
        let mut b3 = fw::Buffer::new(&mut store, 32);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::PROTO_NOT_SET, 0, 0);
        assert!(ml::MplsCodec::ctor(None).encode(&lab, 4, &mut enc, &mut b3, Some(&zero_layer)));
        let out = b3.data().expect("allocate(4) just succeeded");
        assert_eq!(&out[..4], &lab[..4], "the length-0 layer NEVER re-points (:255 &&-arm)");
    }
    // the log seam (cited-NEVER-called in the harness — the U closes vs
    // the donor REAL text_log.o; the port lands ported-by-reading, this
    // unit mirrors it): the :325 bos walk + the :332 format (the leading
    // newline+tab IN the literal face).
    {
        let mut lines = Vec::new();
        let mut lsink = |s: String| lines.push(s);
        ml::MplsCodec::ctor(None).log(&mut lsink, &[0x00, 0x00, 0xF0, 0x0F, 0x00, 0x00, 0xF3, 0x0F]);
        // the :332 face: %05X pads, %hhX stays RAW (tc:0x0 bos:0x0 ttl:0xF
        // — the unpadded C face, NEVER zero-padded by the port):
        assert_eq!(lines[0], "\n\tlabel:0x0000F tc:0x0 bos:0x0 ttl:0xF"); // the filler entry
        assert_eq!(lines[1], "\n\tlabel:0x0000F tc:0x2 bos:0x1 ttl:0xF"); // the bos entry (the raw tc-2 face)
        assert_eq!(lines.len(), 2, "the walk STOPS at bos (:325)");
    }
}

// ==========================================================================
// 8. THE seam + const bridge pins: TUNNEL_MPLS 0x80 == the vectors' mask
//    arm; PROTO_BIT__MPLS 512 RESIDENT (rtn_checks :34) == pb=512 AND the
//    M10 pb=0 faces, with the row source NEVER re-declaring it; the
//    protocol decimals == the vectors' prints; the payload-type enum
//    INDICES (auto 0 / eth 1 / ip4 2 / ip6 3 — the :41 alignment face;
//    §11(d)'s seed-draft eth=2/ip6=4 bound was the drift);
//    MPLS_HEADER_LEN 4 + NUM_RESERVED_LABELS 16; the Parameter RANGE text
//    homes (the faceA PARAM values); the memcpy_s EXACTLY-1 census (the
//    ONE safec face the C15 strip law settled — the Rust mirror lands ONE
//    plain-copy site); the bypass-seam + left-open mirror cites ride the
//    source; the frozen vector line counts.
// ==========================================================================
#[test]
fn up_mpls_seam_consts() {
    const M_RS: &str = include_str!("../src/codecs/cd_mpls.rs");

    // TUNNEL_MPLS 0x80 (snort_config.h:126 sed-pinned) == the mask pair:
    assert_eq!(ml::TUNNEL_MPLS, 0x80);
    assert!(VECTORS.contains("M16 mask80"), "the vectors' mask-armed arm rides the TUNNEL_MPLS face");
    // PROTO_BIT__MPLS RESIDENT (decode_data.h:96 / rtn_checks.rs:34 — the
    // REUSE face; the row-scoped-NEW docs const face STALE): 512 == the
    // pb prints + the 512->0 clear; the row source NEVER re-declares:
    assert_eq!(rtn_checks::PROTO_BIT__MPLS, 512);
    assert!(!M_RS.contains("PROTO_BIT__MPLS: u32"), "the RESIDENT const was re-declared at the row");
    assert!(M_RS.contains("rtn_checks::PROTO_BIT__MPLS"), "the REUSE import face");
    assert!(VECTORS.contains("pb=512") && VECTORS.contains("pb=0"), "the SET+CLEAR pb pair (the :191/:200 arms)");
    // the protocol decimals == the vectors' prints (all-decimal hygiene,
    // never the names):
    assert_eq!(ml::ETHERTYPE_MPLS_UNICAST, 34887);      // protocol_ids.h :153
    assert_eq!(ml::ETHERTYPE_MPLS_MULTICAST, 34888);    // :154
    assert_eq!(fw::protocol_id::MPLS_IP, 137);          // RESIDENT framework/codec.rs :151
    assert_eq!(fw::protocol_id::ETHERTYPE_IPV4, 2048);  // :144 LANDED
    assert_eq!(fw::protocol_id::ETHERTYPE_IPV6, 34525); // :151 LANDED
    assert_eq!(ml::ETHERTYPE_TRANS_ETHER_BRIDGING, 25944); // :147 row twin (trans_bridge/erspan2 precedent)
    assert!(VECTORS.contains("next=34887"), "the init_prot face rides EVERY failure line (NEVER zeroed)");
    // the payload-type enum INDICES (:39-:46 — the :41 parameter-alignment
    // transcription; the seed draft's eth=2/ip6=4 bound was the drift):
    assert_eq!(
        (ml::MPLS_PAYLOADTYPE_AUTODETECT, ml::MPLS_PAYLOADTYPE_ETHERNET, ml::MPLS_PAYLOADTYPE_IPV4, ml::MPLS_PAYLOADTYPE_IPV6),
        (0, 1, 2, 3)
    );
    // the ladder constants (:126/:127):
    assert_eq!(ml::MPLS_HEADER_LEN, 4);
    assert_eq!(ml::NUM_RESERVED_LABELS, 16);
    // the Parameter RANGE-text homing (the landed-shape deviation values —
    // the faceA PARAM print lines):
    assert_eq!(ml::MPLS_PARAM_RANGES[0], ("-1:255", "-1")); // :50
    assert_eq!(ml::MPLS_PARAM_RANGES[1], ("auto | eth | ip4 | ip6", "auto")); // :53
    // the memcpy_s census face (EXACTLY-1 C use-site :267; the Rust port
    // lands the STOCK-shim SEMANTICS = a plain window copy, ONE site):
    assert_eq!(M_RS.matches("head[..n].copy_from_slice").count(), 1, "the :267 shim-semantics mirror lands EXACTLY-1 CODE site");
    assert!(M_RS.contains("memcpy_s"), "the :267 site cites memcpy_s (the stock-safec decision face)");
    // the bypass seam: the landed LEFT-OPEN closure shape (the vxlan/gtp/
    // geneve precedent), NEVER an invented provider:
    assert!(M_RS.contains("bypass(TUNNEL_MPLS)") && M_RS.contains("codec.tunnel_bypass = true"), "the :205-:206 hook seam face");
    // the get_mpls_layer_per_dir left-open mirror (witness_flow the 27-L
    // harness face; the provider CITED flow.h :223, NEVER invented here):
    assert!(M_RS.contains("get_mpls_layer_per_dir"), "the seam cite rides the source");
    assert!(M_RS.contains("witness_flow"), "the harness mirror cite face");
    // the chapter-close honesty face (the ledger cite rides the module doc):
    assert!(M_RS.contains("1465"), "the six-file link-chapter ledger cite rides");
    // the frozen vector identity faces (the NEVER-edit law):
    assert_eq!(VECTORS.lines().count(), 54);
    assert_eq!(VECTORS_FACE_A.lines().count(), 17);
}
