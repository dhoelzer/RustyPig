//! Parity test for the row-18k codecs/misc LEFTOVER TRIO ports — three
//! ground TUs (misc/cd_llc.cc 198 L df63cf75b1bf7642ca80b6a215a0f28c /
//! misc/cd_vxlan.cc 133 L c8479a2aa67ee6af89c22ecc8f763b7d / misc/
//! cd_user.cc 167 L 01e41407b300562c840b4f66a4da4e45; wc 198/133/167 +
//! the 498 SUM re-measured and asserted EVERY build by
//! tools/misc3_harness/build.sh). ZERO-gate row (the daq3/miscip clone):
//! combined gate grep 0 x3 + the misc/test/ CppUTest dialect census
//! STOP-flag probe stays NEGATIVE every build -> this suite carries NO
//! up_gate_* set: honest absence, census-cited.
//!
//! Ground truth #1: `tools/misc3_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 18 L md5 e75f7385779aa89c365dd2ce4a208b67 NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session (per-index assert_eq over want.len()==18). THE R6 EVAL-ORDER
//! RULE REPLAYS: every decode bool lands in a var BEFORE the summary
//! line and every `EV 116 <sid>` lands BETWEEN the decode call and its
//! printf, NEVER sorted. The order/eval faces: :1/:2 (llc 131 BEFORE
//! short2), :4/:5 (132 BEFORE snap7), :3 (the dsap-aa-ssap-00 arm: the
//! cc:105-:106 AND-pair — first operand TRUE second FALSE -> NO event
//! NO SNAP, a TRUE decode: proof the pair gate evaluated FIRST), :10
//! (`VX hook-before-sets cc:73-vs-:76-:79` — the HOOK-eval-before-sets
//! cite line, NEVER a fake decode), :11/:12 (the bypass DUAL FACE:
//! tun_witness_set_mask(0x100) -> bypass=0 vs set_mask(0) -> bypass=1 —
//! both arms print the SAME lyr/pb/next/flags: the hook never mutates
//! anything ELSE, eval cite), :13/:17/:18 the three user CITE lines
//! (witness-SEGV survives / cc:95-:96 else-lyr-0 rides the tcp arm /
//! ioctl-fail + !pci cited-never-armed), :14 the set_key PIN face
//! (sp 12345 + dp 54321 = the ground literals cc:75/:76, the FIXIT-L
//! cc:70 make-configurable debt comment + the dotted-quad pair staying
//! sed-CITES in build.sh).
//!
//! Ground truth #2: `tools/misc3_harness/vectors_faceA.txt` — the
//! FACE-A load/walk face (probe.cc, ONE probe x THREE hidden-BUILDING_SO
//! tables through the in-probe PluginManager witness; the STATIC arms
//! cd_llc/cd_vxlan/cd_user EXIST nm-EXACTLY-1 each), 19 L md5
//! fe1189c6c78139b8828c1a8071e3df28. TRUE NAMES hold x3. THE trio
//! mod_ctor asymmetry PIN replays here: llc 1/1 (REAL LlcModule cc:156/
//! :159, slots :179/:180) vs vxlan 0/0 + user 0/0 — census 1/0/0
//! (contrast daq3 uniform 1/1x3, miscip pair 0/0): the 18i hand-off
//! "do NOT carry the pair 0/0" warning honored through the tables.
//! The GETIDS/GETDLT split also rides: llc 263 / vxlan 264 (GETIDS) vs
//! user GETDLT 230 ONLY (the trio's ONLY data-link registrant; user
//! prints NO GETIDS, the base empty-vector face). The ladder trio names
//! "cd_llc"/"cd_user"/"cd_vxlan" were ALREADY resident (codec_api.rs
//! :117/:129/:131) — this row TURNS them loaded: the daq3-era EXISTENCE-
//! but-UNLOADED posture closes for the trio as the tables land.
//!
//! CppUTest dialect face (PLAN §0/§4, 18f discipline): the misc/test/
//! suites carry EXACTLY 10 CppUTest names (geneve 4 / gtp 3 / teredo 3,
//! TEST_CASE 0 x3) and NONE names a trio TU (build.sh trio-include grep
//! 0 x3 every build) — ALL SEVEN TEST bodies were ALREADY Rust-side
//! translated AT 18f (tests/tun_parity_test.rs up_tun_*). The trio ships
//! ZERO suites of its own: ZERO new up_* translations this row; the
//! census rides as a pinned face with the cross-file contains proof.

use snort3::codecs::cd_llc as llc;
use snort3::codecs::cd_user as usc;
use snort3::codecs::cd_vxlan as vxc;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/misc3_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/misc3_harness/vectors_faceA.txt");
/// The 18f translation site (the CppUTest-dialect cross-file proof).
const TUN_TESTS: &str = include_str!("tun_parity_test.rs");

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 18 lines, ordered,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored;
//    tun_mask folds as the witness table, see tests/tun_parity_test.rs
//    face for the witness_18f body replay).
// ==========================================================================
#[test]
fn misc3_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 18, "vectors.txt must hold the full 18-line DEC ladder");

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
    // the witness_18f CARRIED face: tun_witness_set_mask table + the
    // snort_config.cc:1022 body replay `!((tunnel_mask & proto) or SFDAQ
    // arm)` — the SFDAQ arm rides pinned-false (the 18f witness shape).
    let mut tun_mask: u16;

    let conf = SnortConfig::default();
    // probe's `extern const snort::BaseApi* cd_*[]` + ctor(nullptr):
    let cl = llc::LlcCodec::new();    // al->ctor(nullptr), probe_dec.cc:66
    let cv = vxc::VxlanCodec::new();  // av->ctor(nullptr), probe_dec.cc:83
    let cu = usc::UserCodec::new();   // au->ctor(nullptr), probe_dec.cc:101

    // ---- cd_llc: the two-event ladder + SNAP arms ----
    // vectors:1/:2 — RawData z[4096] zeros, len 2 < 3 (:96/:99 EV 131).
    {
        let z = [0u8; 4096];
        let raw = fw::RawData { data: &z, len: 2 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        let b = cl.decode(&raw, &mut cd, &mut sink); // bool var FIRST (R6)
        push(format!("LLC short2 -> {}", b as i32));
    }
    // vectors:3 — p[3]={0xaa,0x00,0x03}: outer gate (len 3 >= 3) PASSES,
    // the cc:105-:106 AND-pair: dsap hit, ssap 0x00 MISS -> NO event,
    // NO SNAP gate, decode TRUE (the eval-order arm, never a fake EV).
    {
        let p = [0xaa, 0x00, 0x03];
        let raw = fw::RawData { data: &p, len: 3 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        let b = cl.decode(&raw, &mut cd, &mut sink);
        push(format!("LLC dsap-aa-ssap-00 -> {}", b as i32));
    }
    // vectors:4/:5 — p[7]={0xaa,0xaa,0x03}: SNAP pair yes, 7 < 3+5 ->
    // cc:108/:110 EV 132 + false.
    {
        let p = [0xaa, 0xaa, 0x03, 0, 0, 0, 0];
        let raw = fw::RawData { data: &p, len: 7 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        let b = cl.decode(&raw, &mut cd, &mut sink);
        push(format!("LLC snap7 -> {}", b as i32));
    }
    // vectors:6 — p[10] org 0/0/0, proto_id 0x08,0x00: the SNAP happy
    // arm cc:117-:123 (lyr 8, next 2048, flags 4096).
    {
        let p = [0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00, 0x11, 0x22];
        let raw = fw::RawData { data: &p, len: 10 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        let b = cl.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "LLC snap0-org -> {} lyr={} next={} flags={}",
            b as i32,
            cd.lyr_len,
            cd.next_prot_id,
            cd.codec_flags
        ));
    }
    // vectors:7 — org_code[2] 0x0c (the ground's DEAD ETH_ORG_CODE_CDP
    // VALUE as a fixture byte — the define itself NEVER lands): org gate
    // FALSE -> TRUE decode lyr 0.
    {
        let p = [0xaa, 0xaa, 0x03, 0, 0, 0x0c, 0x20, 0x00, 0x11, 0x22];
        let raw = fw::RawData { data: &p, len: 10 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        let b = cl.decode(&raw, &mut cd, &mut sink);
        push(format!("LLC snap-org-nonzero -> {} lyr={}", b as i32, cd.lyr_len));
    }

    // ---- cd_vxlan: the hook + gates ----
    // vectors:8 — z len 7 < 8 (:65 return false, NO event).
    {
        let z = [0u8; 4096];
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cd = fw::CodecData::new(Some(&conf), vxc::PROTOCOL_ID_VXLAN);
        let b = cv.decode(&raw, &mut cd, &mut |_proto| false);
        push(format!("VX len7 -> {}", b as i32));
    }
    // vectors:9 — p[8] flags 0x00 != 0x08 (:70 return false, NO event).
    {
        let p = [0u8; 8];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), vxc::PROTOCOL_ID_VXLAN);
        let b = cv.decode(&raw, &mut cd, &mut |_proto| false);
        push(format!("VX flags-neq8 -> {}", b as i32));
    }
    // vectors:10 — the eval-order CITE line (hook cc:73 rides BEFORE the
    // sets :76-:79); the decode NEVER runs for this line.
    push("VX hook-before-sets cc:73-vs-:76-:79".to_string());
    // vectors:11 — tun_witness_set_mask(0x100) (probe_dec.cc:90): the
    // TUNNEL_VXLAN bit SET -> enabled FALSE -> bypass stays FALSE; the
    // sets land (lyr 8 pb 262144 next 261 flags 512).
    {
        tun_mask = 0x100; // probe_dec.cc:90
        let p = [0x08, 0, 0, 0, 0, 0, 0, 0];
        let raw = fw::RawData { data: &p, len: 88 };
        let mut cd = fw::CodecData::new(Some(&conf), vxc::PROTOCOL_ID_VXLAN);
        let b = cv.decode(&raw, &mut cd, &mut |proto| !((tun_mask & proto) != 0));
        push(format!(
            "VX mask256 -> {} lyr={} pb={} next={} flags={} bypass={}",
            b as i32,
            cd.lyr_len,
            cd.proto_bits,
            cd.next_prot_id,
            cd.codec_flags,
            cd.tunnel_bypass as i32
        ));
    }
    // vectors:12 — set_mask(0) (probe_dec.cc:94): mask 0 -> enabled TRUE
    // -> cc:74 tunnel_bypass = true (the DUAL FACE pair).
    {
        tun_mask = 0; // probe_dec.cc:98 re-arms 0 (already 0 post-:94)
        let p = [0x08, 0, 0, 0, 0, 0, 0, 0];
        let raw = fw::RawData { data: &p, len: 88 };
        let mut cd = fw::CodecData::new(Some(&conf), vxc::PROTOCOL_ID_VXLAN);
        let b = cv.decode(&raw, &mut cd, &mut |proto| !((tun_mask & proto) != 0));
        push(format!(
            "VX mask0 -> {} lyr={} pb={} next={} flags={} bypass={}",
            b as i32,
            cd.lyr_len,
            cd.proto_bits,
            cd.next_prot_id,
            cd.codec_flags,
            cd.tunnel_bypass as i32
        ));
    }
    // ---- cd_user: the witness-channel face ----
    // vectors:13 — the honest CITE line: ground cc:103 chain-calls
    // get_local_instance()->ioctl() WITHOUT a null check (the ground
    // SEGV face); survives ONLY because the SYNTHETIC witness ioctl
    // NEVER derefs `this` (witness_trio.cc:27-:34, cite-never-fix).
    push("US no-instance ground-SEGV cc:103 chain-call, witness-ioctl survives".to_string());
    // vectors:14 — m[16] all zeros: ip_proto 0 -> set_key cc:116-:120
    // (pb=2 TYPE arm, sp 12345 dp 54321 = ground literals cc:75/:76,
    // set_flags else lyr=0) + PktType FILE 6. RawData daq_msg channel =
    // the non-null zeroed buffer (the witness memcpy face).
    {
        let m = [0u8; 16];
        let raw = fw::RawData { data: &[], len: 0 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::IP);
        let mut d = usc::UserDecodeData::default();
        let b = cu.decode(&raw, &mut cd, &mut d, Some(&m));
        push(format!(
            "US proto0-key -> {} pb={} sp={} dp={} type={} lyr={}",
            b as i32,
            cd.proto_bits,
            d.sp,
            d.dp,
            d.pkt_type,
            cd.lyr_len
        ));
    }
    // vectors:15 — m[12]=6 (TCP) m[13]=1 (TO_SERVER) ports @8=12345:
    // set_ip TCP pb=2 sp 12345 dp 0 (else slot) + USER 5 + C2S 512;
    // END_FLOW missing -> the cc:95-:96 ELSE lyr 0 rides LIVE here.
    {
        let mut m = [0u8; 16];
        m[12] = 6;
        m[13] = 0x01;
        m[8..10].copy_from_slice(&12345u16.to_le_bytes()); // probe *(uint16_t*)(m+8)=12345 on the LE host
        let raw = fw::RawData { data: &[], len: 0 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::IP);
        let mut d = usc::UserDecodeData::default();
        let b = cu.decode(&raw, &mut cd, &mut d, Some(&m));
        push(format!(
            "US tcp-c2s -> {} pb={} sp={} dp={} type={} df={} lyr={}",
            b as i32,
            cd.proto_bits,
            d.sp,
            d.dp,
            d.pkt_type,
            d.decode_flags,
            cd.lyr_len
        ));
    }
    // vectors:16 — m[12]=17 (UDP) m[13]=0x07 (all three flags) ports
    // 20000/30000, raw len 4: UDP pb=4, C2S|SOF|EOF 3584, END_FLOW ->
    // lyr = raw.len 4 (cc:93), USER 5.
    {
        let mut m = [0u8; 16];
        m[12] = 17;
        m[13] = 0x07;
        m[8..10].copy_from_slice(&20000u16.to_le_bytes()); // probe htons face == LE slot
        m[10..12].copy_from_slice(&30000u16.to_le_bytes());
        let raw = fw::RawData {
            data: b"pay",
            len: 4,
        };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::IP);
        let mut d = usc::UserDecodeData::default();
        let b = cu.decode(&raw, &mut cd, &mut d, Some(&m));
        push(format!(
            "US udp-flags7 -> {} pb={} sp={} dp={} df={} lyr={} type={}",
            b as i32,
            cd.proto_bits,
            d.sp,
            d.dp,
            d.decode_flags,
            cd.lyr_len,
            d.pkt_type
        ));
    }
    // vectors:17 — the else-lyr-0 arms CITE line (rides the tcp-c2s arm
    // above: flags 0x01, NO END_FLOW -> cc:96 lyr 0).
    push("US arms-cc:95-:96-else-lyr0-face".to_string());
    // vectors:18 — the NEVER-armed cites CITE line: the != DAQ_SUCCESS
    // leg cc:103-:104 + the !pci leg cc:108; the witness ALWAYS returns
    // DAQ_SUCCESS and ALWAYS fills pci (witness_trio.cc:31-:33).
    push("US ioctl-fail cc:103 + !pci cc:108 cited-never-armed witness-always-success/fills".to_string());

    assert_eq!(got_len(&out), 18);
    let got = out.borrow();
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

fn got_len(out: &std::rc::Rc<std::cell::RefCell<Vec<String>>>) -> usize {
    out.borrow().len()
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 19 lines (probe.cc in-probe
//    load_plugins witness walking the THREE hidden-BUILDING_SO tables
//    through the STATIC arms — the tables ARE cd_llc/cd_vxlan/cd_user,
//    nm EXACTLY-1 each, PLAN §1/§7).
// ==========================================================================
#[test]
fn misc3_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 19, "vectors_faceA.txt must hold the full 19-line walk");

    let mut got: Vec<String> = Vec::new();

    // the witness load face: for (; p && *p; ++p) printf("LOAD %s\n", (*p)->name)
    for tab in [llc::CD_LLC, vxc::CD_VXLAN, usc::CD_USER] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
    }
    got.push("LOADS 3".to_string());

    // probe.cc tabs[] = { cd_llc[0], cd_vxlan[0], cd_user[0] } — TRUE
    // NAMES x3 (file base == table base == NAME walk face; NO drift
    // rider this row): API/HELP/mod-pair/ctor lines in probe order.
    let tabs = [llc::CD_LLC, vxc::CD_VXLAN, usc::CD_USER];
    let nm = ["llc", "vxlan", "user"];
    for (tag, tab) in nm.iter().zip(tabs.iter()) {
        let a = tab[0];
        got.push(format!(
            "API {} type={} size={} ver={} name={}",
            tag, a.ptype, a.size, a.api_version, a.name
        ));
        got.push(format!("HELP {} {}", tag, a.help));
        // THE trio asymmetry PIN: 1/1 (llc REAL cc:156/:159 slots :179/
        // :180) vs 0/0 x2 (vxlan :113/:114 nullptr plain, user :147/:148
        // EXPLICIT-comment nullptr pair) — census 1/0/0 faceA:7/:12/:17.
        got.push(format!(
            "{} mod_ctor={} mod_dtor={}",
            tag, a.mod_ctor as u8, a.mod_dtor as u8
        ));
        // ca->ctor(nullptr); ctor/dtor presence faceA:8/:13/:18:
        got.push(format!("{} ctor={} dtor={}", tag, a.ctor as u8, a.dtor as u8));
        // c->get_protocol_ids(ids) — the llc/vxlan overrides land (263/
        // 264 DECIMAL); user rides the C base EMPTY vector (no override
        // cc:37-:44 — NO GETIDS user line exists in the transcript):
        match *tag {
            "llc" => {
                let mut ids = Vec::new();
                llc::LlcCodec::new().get_protocol_ids(&mut ids);
                for id in ids {
                    got.push(format!("GETIDS {tag} {id}")); // 0x0107 = 263
                }
            }
            "vxlan" => {
                let mut ids = Vec::new();
                vxc::VxlanCodec::new().get_protocol_ids(&mut ids);
                for id in ids {
                    got.push(format!("GETIDS {tag} {id}")); // 0x0108 = 264
                }
            }
            _ => {} // user: C base empty-vector face, zero GETIDS lines
        }
        // c->get_data_link_type(dlts) — the user override lands (230);
        // llc/vxlan ride C base EMPTY (no override — no GETDLT line):
        if *tag == "user" {
            let mut dlts = Vec::new();
            usc::UserCodec::new().get_data_link_type(&mut dlts);
            for d in dlts {
                got.push(format!("GETDLT {tag} {d}")); // DLT_USER 230
            }
        }
        // ca->dtor(c): the stack-owned Rust fold (18d posture), silent.
    }

    assert_eq!(got.len(), 19);
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "faceA line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 3. HIDDEN-TABLE tripwire — the trio table-face pins. The C tables live
//    under the hidden `#ifdef BUILDING_SO` split (sed-verbatim in build.sh
//    EVERY build): cd_llc.cc :190-:197 (static arm :193, feed :196) /
//    cd_vxlan.cc :124-:132 (arm :127, feed :130) / cd_user.cc :158-:166
//    (arm :161, feed :164) — the 18j hidden-table census EXTENDED x3.
//    Rust face = the landed-row pattern: table const identity pins the C
//    table name, feed identity pins the record, ZERO #[no_mangle].
// ==========================================================================
#[test]
fn misc3_hidden_table_tripwire() {
    const LLC_RS: &str = include_str!("../src/codecs/cd_llc.rs");
    const VX_RS: &str = include_str!("../src/codecs/cd_vxlan.rs");
    const US_RS: &str = include_str!("../src/codecs/cd_user.rs");
    // THE hidden-table NAME pins (cites cd_llc.cc:193 / cd_vxlan.cc:127
    // / cd_user.cc:161 static-arm statements — renaming a const trips
    // THIS assert; the daq3/small4/miscip drift-tripwire posture):
    assert!(LLC_RS.contains("pub const CD_LLC: CodecTable = &[&LLC_API];"),
        "the cd_llc hidden-table const face drifted");
    assert!(VX_RS.contains("pub const CD_VXLAN: CodecTable = &[&VXLAN_API];"),
        "the cd_vxlan hidden-table const face drifted");
    assert!(US_RS.contains("pub const CD_USER: CodecTable = &[&USER_API];"),
        "the cd_user hidden-table const face drifted");
    // the hidden-BUILDING_SO cite lines ride ALL THREE source faces (the
    // doc cites survive line-wrapping — check the two fragments):
    assert!(LLC_RS.contains("const BaseApi*") && LLC_RS.contains("cd_llc[]")); // the cc:193 static-arm cite
    assert!(VX_RS.contains("const BaseApi*") && VX_RS.contains("cd_vxlan[]")); // the cc:127 static-arm cite
    assert!(US_RS.contains("const BaseApi*") && US_RS.contains("cd_user[]"));  // the cc:161 static-arm cite
    // ZERO #[no_mangle] in the trio (the src-wide landed pattern, the
    // grep face the harness re-pins build.sh-side too):
    assert!(!LLC_RS.contains("#[no_mangle]"));
    assert!(!VX_RS.contains("#[no_mangle]"));
    assert!(!US_RS.contains("#[no_mangle]"));

    // EXACTLY-1 entry per table == the `{ &*_api.base, nullptr }` C face
    // (the harness walk loaded EXACTLY 3, vectors_faceA:4 `LOADS 3`):
    assert_eq!(llc::CD_LLC.len(), 1);
    assert_eq!(vxc::CD_VXLAN.len(), 1);
    assert_eq!(usc::CD_USER.len(), 1);

    // feed identity (cc:196 / cc:130 / cc:164 feed &*_api.base):
    assert!(std::ptr::eq(llc::CD_LLC[0], &llc::LLC_API));
    assert!(std::ptr::eq(vxc::CD_VXLAN[0], &vxc::VXLAN_API));
    assert!(std::ptr::eq(usc::CD_USER[0], &usc::USER_API));

    // TRUE-NAME trio x3 (file base == table base == NAME): the ladder
    // entries ride STATIC_CODEC_EXTERN_NAMES RESIDENT (:117/:129/:131 —
    // NEVER re-touched; externs codec_api.cc :59/:71/:73 + loads :104/
    // :116/:118 cite-pinned every build). THIS row TURNS the trio loaded
    // (the tables exist in the Rust face now — the EXISTENCE-but-UNLOADED
    // posture closes for these three names exactly like the 18j pair's):
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_llc"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_user"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_vxlan"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18k adds NO new externs"
    );

    // NAME side (the walk prints these words, faceA:5-:6/:10-:11/:15-:16):
    assert_eq!(llc::LLC_NAME, "llc");              // cc:30
    assert_eq!(llc::LLC_API.name, "llc");          // cc:177 slot
    assert_eq!(vxc::CD_VXLAN_NAME, "vxlan");       // cc:31
    assert_eq!(vxc::VXLAN_API.name, "vxlan");      // cc:111 slot
    assert_eq!(usc::CD_NAME, "user");              // cc:33
    assert_eq!(usc::USER_API.name, "user");        // cc:145 slot
}

// ==========================================================================
// 4. THE record census — THE trio asymmetry 1/0/0 (llc mod pair REAL vs
//    vxlan/user nullptr pairs): 112/1900547/PT_CODEC x3 + ctor/dtor set +
//    the four g/t nullptr arms false x4 everywhere + the HELP faces.
// ==========================================================================
#[test]
fn misc3_record_census() {
    for a in [llc::LLC_API, vxc::VXLAN_API, usc::USER_API] {
        assert_eq!(a.ptype, fw::PT_CODEC);
        assert_eq!(a.size, 112); // sizeof(CodecApi), the faceA:5/:10/:15 pin
        assert_eq!(a.api_version, 1900547);
        assert_eq!(a.version, 0);
        assert_eq!(a.features, fw::PLUGIN_SO_RELOAD);
        assert_eq!(a.options, fw::API_OPTIONS);
        assert!(!a.pinit);
        assert!(!a.pterm);
        assert!(!a.tinit);
        assert!(!a.tterm);
        assert!(a.ctor);
        assert!(a.dtor);
    }
    // THE asymmetry PIN (census 1/0/0 — faceA:7/:12/:17): llc the trio's
    // ONLY real module (mod_ctor() cc:156 + mod_dtor() cc:159, slots :179/
    // :180; the Rust mod_ctor face is llc::LlcModule::new, 18i posture);
    // vxlan plain nullptr pair cc:113/:114; user EXPLICIT-comment nullptr
    // pair cc:147/:148. Contrast daq3 1/1/1 + miscip 0/0 — NOT carried.
    // The record fields ARE compile-time consts — the pinned-const assert
    // face is intentional (the ext_parity_test.rs:587 /
    // small4_parity_test.rs:594 assertions_on_constants precedent):
    #[allow(clippy::assertions_on_constants)] // pinned record-const face (lineage precedent, point-site)
    {
        assert!(llc::LLC_API.mod_ctor, "llc mod_ctor MUST be the REAL arm (slots :179/:180)");
        assert!(llc::LLC_API.mod_dtor, "llc mod_dtor MUST be the REAL arm");
        assert!(!vxc::VXLAN_API.mod_ctor, "vxlan mod_ctor MUST be the nullptr arm");
        assert!(!vxc::VXLAN_API.mod_dtor, "vxlan mod_dtor MUST be the nullptr arm");
        assert!(!usc::USER_API.mod_ctor, "user mod_ctor MUST be the nullptr arm");
        assert!(!usc::USER_API.mod_dtor, "user mod_dtor MUST be the nullptr arm");
    }

    // llc module face: the REAL LlcModule lands Rust-side (the trio's
    // ONLY BaseCodecModule subclass): 2-arg base ctor slots NAME/HELP.
    use snort3::codecs::codec_module as cm;
    let m = llc::LlcModule::new();
    assert_eq!(m.base.name, "llc"); // cc:45 the BaseCodecModule(LLC_NAME, LLC_HELP) slots
    assert_eq!(m.base.help, llc::LLC_HELP);
    assert_eq!(cm::rule_count(&llc::LLC_RULES), 2, "llc_rules = TWO rows + terminator (cc:35-:39)");
    assert_eq!(cm::CodecSid::DECODE_BAD_LLC_HEADER as u32, 131);   // h:80
    assert_eq!(cm::CodecSid::DECODE_BAD_LLC_OTHER as u32, 132);    // h:81
    assert_eq!(llc::LLC_RULES[0].sid, 131); // cc:37
    assert_eq!(llc::LLC_RULES[1].sid, 132); // cc:38
    assert_eq!(llc::LLC_RULES[2].sid, 0);   // cc:39 terminator

    // HELP faces (faceA:6/:11/:16; the sed pins cc:31 / cc:32 / cc:34-:35):
    assert_eq!(llc::LLC_API.help, "support for logical link control");
    assert_eq!(vxc::VXLAN_API.help, "support for Virtual Extensible LAN");
    assert_eq!(usc::USER_API.help, "support for user sessions (DLT 230)");
    // the ADD_DLT splice recipe pin (codec.h:52, the cd_raw.rs:48 fn):
    use snort3::codecs::cd_raw as rawc;
    assert_eq!(rawc::add_dlt(usc::CD_HELP_STR, usc::DLT_USER), usc::CD_HELP); // cc:35 splice
}

// ==========================================================================
// 5. The misc/test/ CppUTest dialect census (PLAN §0/§4, STOP-flag probe
//    NEGATIVE): EXACTLY 10 names on disk — TEST_GROUP x3 + TEST( x7 =
//    geneve 4 / gtp 3 / teredo 3, TEST_CASE 0 x3, trio-TU refs 0 x3
//    (build.sh re-runs every build). ALL SEVEN bodies were translated
//    Rust-side AT 18f (cross-file contains reads the ACTUAL 18f file);
//    the trio owns ZERO suites: ZERO new up_* translations this row.
// ==========================================================================
#[test]
fn misc3_cpputest_dialect_census() {
    // The 10 measured names (ground cites: geneve_codec_test.cc:103/
    // :107/:121/:150, gtp_codec_test.cc:87/:93/:116, teredo_codec_test
    // .cc:86/:90/:103 — the miscip test pins the SAME ten; re-pinned
    // here against the TRIO names specifically):
    const NAMES: [&str; 10] = [
        "TEST_GROUP(geneve_codec_tests)",
        "TEST(geneve_codec_tests, decode)",
        "TEST(geneve_codec_tests, geneve_lyr)",
        "TEST(geneve_codec_tests, geneve_lyr_no_options)",
        "TEST_GROUP(gtp_codec_tests)",
        "TEST(gtp_codec_tests, gtpv1_header_fills_packet_no_inner_read)",
        "TEST(gtp_codec_tests, gtpv0_header_fills_packet_no_inner_read)",
        "TEST_GROUP(teredo_codec_tests)",
        "TEST(teredo_codec_tests, rejects_payload_ending_after_origin_indicator)",
        "TEST(teredo_codec_tests, rejects_payload_ending_after_auth_indicator)",
    ];
    let per_suite = |needle: &str| NAMES.iter().filter(|n| n.contains(needle)).count();
    assert_eq!(per_suite("geneve_codec_tests"), 4, "geneve 1 GROUP + 3 TEST");
    assert_eq!(per_suite("gtp_codec_tests"), 3, "gtp 1 GROUP + 2 TEST");
    assert_eq!(per_suite("teredo_codec_tests"), 3, "teredo 1 GROUP + 2 TEST");

    // ZERO names reference the trio (the build.sh trio-include grep 0 x3
    // face — the misc trio ships NO suite of its own; build.sh re-runs
    // the ground-side grep EVERY build, the STOP-flag tripwire):
    for n in NAMES.iter() {
        assert!(!n.contains("llc") && !n.contains("vxlan") && !n.contains("user"),
            "census lie: {n}");
    }

    // The 18f translations EXIST (all 7 TEST names mirrored up_tun_* —
    // the air-check reads the ACTUAL landed file, the miscip posture):
    assert!(TUN_TESTS.contains("fn up_tun_geneve_decode"));
    assert!(TUN_TESTS.contains("fn up_tun_geneve_geneve_lyr("));
    assert!(TUN_TESTS.contains("fn up_tun_geneve_geneve_lyr_no_options"));
    assert!(TUN_TESTS.contains("fn up_tun_gtp_gtpv1_header_fills_packet_no_inner_read"));
    assert!(TUN_TESTS.contains("fn up_tun_gtp_gtpv0_header_fills_packet_no_inner_read"));
    assert!(TUN_TESTS.contains("fn up_tun_teredo_rejects_payload_ending_after_auth_indicator"));
    assert!(TUN_TESTS.contains("fn up_tun_teredo_rejects_payload_ending_after_origin_indicator"));
}

// ==========================================================================
// 6. UNIT: the llc AND-pair gate + SNAP legs + the dead-define token-zero
//    census (R3 cite-NEVER-land, build.sh re-pins ground grep-count 1 x6
//    every build; the Rust token-zero face pinned HERE).
// ==========================================================================
#[test]
fn up_misc3_llc_arms_and_dead_defines() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = llc::LlcCodec::new();

    // the AND-pair FIRST-operand faces x2 (cc:105-:106): aa/00 (ssap
    // miss, the vectors:3 arm) + 00/aa (dsap miss, mirror arm) -> TRUE
    // decode, ZERO events, NO SNAP.
    for p in [
        [0xaa, 0x00, 0x03], // vectors:3 (ssap operand FALSE)
        [0x00, 0xaa, 0x03], // mirror (dsap operand FALSE)
    ] {
        let raw = fw::RawData { data: &p, len: 3 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        assert!(c.decode(&raw, &mut cd, &mut sink));
        assert_eq!(std::mem::take(&mut *evs.borrow_mut()).len(), 0, "AND-pair miss = NO event");
        assert_eq!(cd.lyr_len, 0, "no SNAP arm after the pair miss");
    }
    // outer gate x2: len 0 + len 2 -> 131 each (cc:96-:100).
    for len in [0u32, 2] {
        let z = [0u8; 4];
        let raw = fw::RawData { data: &z, len };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        assert!(!c.decode(&raw, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 131)]);
    }
    // inner gate: pair OK + len 7 < 8 -> 132 (boundary: len 3..7 all
    // ride it — MEASURED 3,5,7 arms; len exactly 8 = sizeof pair, the
    // probe comment face).
    for len in [3u32, 5, 7] {
        let p = [0xaa, 0xaa, 0x03, 0, 0, 0, 0];
        let raw = fw::RawData { data: &p, len };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        assert!(!c.decode(&raw, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 132)]);
    }
    // org-gate leg census (cc:117-:119, var-first triple): ANY nonzero
    // org byte -> TRUE lyr 0; ALL zero -> the lyr 8 face at len 8:
    {
        let p = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 }; // EXACTLY 8 = 3+5 boundary
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        assert!(c.decode(&raw, &mut cd, &mut sink));
        assert_eq!(cd.lyr_len, 8);
        assert_eq!(cd.next_prot_id, 0x0800); // proto() @6..7 BE
        assert_eq!(cd.codec_flags, fw::CODEC_ETHER_NEXT);
        assert_eq!(std::mem::take(&mut *evs.borrow_mut()).len(), 0);
    }
    for bad in [[0x0c, 0, 0], [0, 0x0c, 0], [0, 0, 0x0c]] {
        let mut p = [0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00];
        p[3..6].copy_from_slice(&bad);
        let raw = fw::RawData { data: &p, len: 10 };
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERNET_LLC);
        assert!(c.decode(&raw, &mut cd, &mut sink));
        assert_eq!(cd.lyr_len, 0);
    }

    // DEAD-define token-zero (R3): the SIX ground dead names NEVER land
    // (build.sh re-pins ground grep-count 1 x6 = #define-only; the two
    // USED names DO land as consts with grep-count 3 ground-side):
    const LLC_RS: &str = include_str!("../src/codecs/cd_llc.rs");
    for dead in ["ETH_DSAP_SNA", "ETH_SSAP_SNA", "ETH_DSAP_STP", "ETH_SSAP_STP", "ETH_ORG_CODE_ETHR", "ETH_ORG_CODE_CDP"] {
        assert!(!LLC_RS.contains(dead), "dead define {dead} must cite-NEVER-land");
    }
    assert_eq!(llc::ETH_DSAP_IP, 0xaa); // cc:84 USED face
    assert_eq!(llc::ETH_SSAP_IP, 0xaa); // cc:85
    // the used-names grep census ground-side (harness mirror):
    assert_eq!(llc::ETH_LLC_SIZE, 3);  // sizeof(EthLlc), the cc:96 gate
    assert_eq!(llc::ETH_LLC_OTHER_SIZE, 5); // the cc:108/cc:121 3+5 face
}

// ==========================================================================
// 7. UNIT: the vxlan HOOK dual face + the eval-order pin + gates (the
//    18f witness_18f CARRIED replay — EXACTLY zero new bypass symbols).
// ==========================================================================
#[test]
fn up_misc3_vxlan_hook_pair() {
    let conf = SnortConfig::default();
    let run = |mask: u16| -> (bool, bool, u32) {
        let tun_mask = mask; // the closure reads (Copy capture = Fn face, coerces to &mut dyn FnMut)
        let p = [0x08, 0, 0, 0, 1, 2, 3, 0]; // flags 0x08 + a VNI fixture
        let raw = fw::RawData { data: &p, len: 88 };
        let mut cd = fw::CodecData::new(Some(&conf), vxc::PROTOCOL_ID_VXLAN);
        let b = vxc::VxlanCodec::new().decode(&raw, &mut cd, &mut |proto| !((tun_mask & proto) != 0));
        (b, cd.tunnel_bypass, cd.proto_bits)
    };
    // HOOK FALSE arm (TUNNEL_VXLAN bit set -> enabled false): the sets
    // ride, bypass FALSE (vectors:11 face).
    assert_eq!(run(0x100), (true, false, 262144));
    // HOOK TRUE arm (mask 0 -> enabled true -> cc:74): same sets, bypass
    // TRUE (vectors:12 face). The DUAL pair pins the hook mutates ONLY
    // tunnel_bypass — eval order rides the cite line vectors:10.
    assert_eq!(run(0), (true, true, 262144));

    // gates: two NO-EVENT returns (the trio's zero-event asymmetry — NO
    // sink in the signature, the cd_teredo face): len 7 + flags arms.
    let z = [0u8; 16];
    let mut cd = fw::CodecData::new(Some(&conf), vxc::PROTOCOL_ID_VXLAN);
    assert!(!vxc::VxlanCodec::new().decode(&fw::RawData { data: &z, len: 7 }, &mut cd, &mut |_| false));
    assert_eq!((cd.lyr_len, cd.proto_bits), (0, 0), "gate legs NEVER set anything (eval order)");
    let f = [0u8; 8];
    assert!(!vxc::VxlanCodec::new().decode(&fw::RawData { data: &f, len: 8 }, &mut cd, &mut |_| false));
    let ok = [0x08, 0, 0, 0, 0, 0, 0, 0];
    assert!(vxc::VxlanCodec::new().decode(&fw::RawData { data: &ok, len: 8 }, &mut cd, &mut |_| false));
    assert_eq!(cd.lyr_len, 8); // len EXACTLY 8 = the VXLAN_MIN_HDR_LEN boundary
    assert_eq!(cd.next_prot_id, fw::protocol_id::ETHERNET_802_3); // the IMPORT face == 261
    assert_eq!(fw::protocol_id::ETHERNET_802_3, 0x0105);          // protocol_ids.h:132
    // the VNI helper (the log face, cite-never-vectorized — helper-only
    // pin): 0x010203 over @4..6.
    let vni = [0x08, 0, 0, 0, 1, 2, 3, 0];
    assert_eq!(vxc::vxlan_vni(&vni), 0x01_0203); // cc:88
}

// ==========================================================================
// 8. UNIT: the user witness-mirror channel + the set_key PIN + the
//    row-scoped vocab census + the cite-NEVER-armed legs.
// ==========================================================================
#[test]
fn up_misc3_user_witness_and_vocab() {
    let conf = SnortConfig::default();

    // THE witness-mirror seam fn (sfdaq_query_usr_pci, the get_proto_name
    // precedent): Some(zeroed) = the probe non-null memcpy face -> the
    // ip_proto==0 set_key arm; NONE = the witness memset face (proven
    // EQUIVALENT here — the probe NEVER exercises None, the fixture face
    // stays honest); the ioctl-fail + !pci legs NEVER fire THROUGH the
    // seam (witness-always-success/fills, vectors:18).
    let zeros = [0u8; 16];
    let a = usc::sfdaq_query_usr_pci(Some(&zeros));
    let b = usc::sfdaq_query_usr_pci(None);
    assert_eq!(a, b, "the zeroed-msg memcpy face == the memset face (probe fixture equivalence)");
    assert_eq!(a, [0u8; usc::DAQ_USR_HDR_SIZE]); // sizeof(DAQ_UsrHdr_t)=14 (daqs/daq_user.h :36-:44)

    // set_key PIN face (THE FIXIT-L hardcoded observable): pb 2 + sp
    // 12345 + dp 54321 + FILE 6 (cc:74-:78; the ground literals cc:75/:76
    // ARE the observable, addresses NEVER land — tripwire right below).
    {
        let m = [0u8; 16];
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::IP);
        let mut d = usc::UserDecodeData::default();
        assert!(usc::UserCodec::new().decode(&fw::RawData { data: &[], len: 0 }, &mut cd, &mut d, Some(&m)));
        assert_eq!((cd.proto_bits, d.sp, d.dp, d.pkt_type), (2, 12345, 54321, 6)); // cc:75/:76/:119
        assert_eq!(d.decode_flags, 0);             // flags 0 -> zero legs, else lyr 0
        assert_eq!(cd.lyr_len, 0);                 // cc:96 the ELSE arm
    }
    // the set_flags trio arms, unit-decomposed (cc:84-:96): each flag leg
    // independent + the END_FLOW->lyr=raw.len vs ELSE split.
    let flags_face = |flags: u8| -> (u64, u16) {
        let mut m = [0u8; 16];
        m[12] = 17; // UDP leg (the else arm cc:65)
        m[13] = flags;
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::IP);
        let mut d = usc::UserDecodeData::default();
        assert!(usc::UserCodec::new().decode(&fw::RawData { data: b"abcd", len: 4 }, &mut cd, &mut d, Some(&m)));
        (d.decode_flags, cd.lyr_len)
    };
    assert_eq!(flags_face(0x01), (512, 0));   // C2S, ELSE lyr 0 (cc:84-:85/:96)
    assert_eq!(flags_face(0x02), (1024, 0));  // SOF (cc:87-:88)
    assert_eq!(flags_face(0x04), (2048, 4));  // EOF + lyr 4 (cc:90-:93)
    assert_eq!(flags_face(0x07), (3584, 4));  // vectors:16 full pair
    assert_eq!(usc::DECODE_C2S + usc::DECODE_SOF + usc::DECODE_EOF, 3584); // decode_data.h :146-:148 PYPIN sum

    // the TCP discriminator arm (cc:62-:63, IMPORT face ip_protocol::TCP):
    {
        let mut m = [0u8; 16];
        m[12] = 6;
        m[13] = 0x01;
        m[8..10].copy_from_slice(&12345u16.to_le_bytes());
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::IP);
        let mut d = usc::UserDecodeData::default();
        assert!(usc::UserCodec::new().decode(&fw::RawData { data: &[], len: 0 }, &mut cd, &mut d, Some(&m)));
        assert_eq!((cd.proto_bits, d.sp, d.dp, d.pkt_type), (2, 12345, 0, 5)); // USER 5 (cc:114)
    }

    // row-scoped vocab census w/ cites (the build.sh PYPIN pairs both
    // ways ground-side EVERY build):
    assert_eq!(usc::DLT_USER, 230);                    // daqs/daq_user.h :29 (faceA:19 GETDLT)
    assert_eq!(usc::DAQ_USR_FLAG_TO_SERVER, 0x01);     // :32
    assert_eq!(usc::DAQ_USR_FLAG_START_FLOW, 0x02);    // :33
    assert_eq!(usc::DAQ_USR_FLAG_END_FLOW, 0x04);      // :34
    assert_eq!(usc::DIOCTL_QUERY_USR_PCI, 2048);       // :46 (the cc:103 arg)
    assert_eq!(usc::PKT_TYPE__USER, 5);                // decode_data.h :45-:48 USER index
    assert_eq!(usc::PKT_TYPE__FILE, 6);                // FILE index
    assert_eq!(usc::PROTO_BIT__TCP, 2);                // decode_data.h :88 (cd_udp.rs:155 twin family)
    assert_eq!(usc::PROTO_BIT__UDP, 4);                // :89
    use snort3::codecs::cd_udp as udp;
    assert_eq!(usc::PROTO_BIT__UDP, udp::PROTO_BIT__UDP); // the dup-not-import ruling face (cd_icmp6.rs:179-:183)
    // the vxlan row vocab:
    assert_eq!(vxc::PROTO_BIT__VXLAN, 262144);         // decode_data.h :105 (zero prior Rust face)
    assert_eq!(vxc::TUNNEL_VXLAN, 0x100);              // snort_config.h :127 (vector label mask256)
    assert_eq!(vxc::PROTOCOL_ID_VXLAN, 0x0108);        // protocol_ids.h :135
    assert_eq!(vxc::PROTOCOL_ID_VXLAN, udp::PROTOCOL_ID_VXLAN); // the cd_udp.rs :147 twin (dup face re-pinned)
    // llc IMPORT faces (framework protocol_id family, NEVER re-authored):
    assert_eq!(fw::protocol_id::ETHERNET_LLC, 0x0107); // :134 (GETIDS llc 263)
    assert_eq!(fw::protocol_id::ETHERNET_LLC, 263);    // DECIMAL faceA:9
    assert_eq!(vxc::PROTOCOL_ID_VXLAN, 264);           // DECIMAL faceA:14
    assert_eq!(fw::CODEC_ETHER_NEXT, 4096);            // codec.h (vectors:6 flags)
    assert_eq!(fw::CODEC_NON_IP_TUNNEL, 512);          // codec.h (vectors:11/:12 flags)

    // the cite-NEVER-land tripwire: the set_key dotted-quad pair NEVER
    // appears in the Rust face (the build.sh sed-cites cc:72 ONLY; the
    // ground literals 12345/54321 DO land = the observable ruling).
    const US_RS: &str = include_str!("../src/codecs/cd_user.rs");
    assert!(!US_RS.contains("192.168."));
    assert!(US_RS.contains("12345") && US_RS.contains("54321"));
    assert!(US_RS.contains("FIXIT-L make configurable")); // the cc:70 debt comment rides
}
