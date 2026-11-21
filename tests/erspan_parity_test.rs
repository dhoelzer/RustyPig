//! Parity test for the row-18l codecs/link CHEAP SUB-TRIO ports — three
//! ground TUs (link/cd_erspan2.cc 145 L fee3934f71fe1c77cf3c0aef120e7eec /
//! link/cd_erspan3.cc 147 L 8ba0422c85300be2f799c6e24b4b8086 / link/
//! cd_trans_bridge.cc 158 L 20a6a8b0ee1b4c1f9b66e10fe7c00db9; wc 145/147/
//! 158 + the 450 SUM re-measured and asserted EVERY build by
//! tools/erspan_harness/build.sh). ZERO-gate row (19th straight honest
//! face): find src/codecs/link -type d -name test = 0 — the link dir has
//! NO test/ AT ALL + add_cpputest census 0 → this suite carries NO
//! up_gate_* set: honest absence, census-cited.
//!
//! Ground truth #1: `tools/erspan_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 18 L md5 7d7d350073eda41074120532c65146bf NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session (per-index assert_eq over want.len()==18). THE R6 EVAL-ORDER
//! RULE REPLAYS: every decode bool lands in a var BEFORE the summary
//! line and every `EV 116 <sid>` lands BETWEEN the decode call and its
//! printf, NEVER sorted. THE shared-462 face: vectors:3 + :9 —
//! DECODE_ERSPAN_HDR_VERSION_MISMATCH fires on BOTH siblings EXACTLY-2
//! (the (a1) version-check story, erspan2 cc:87 !=0x01 / erspan3 cc:89
//! !=0x02). The order-site cite line (:13) pairs the two inverse happy-
//! arm write orders (E2 lyr:93-before-next:94 vs E3 next:95-before-
//! lyr:96). The session-id (:6/:12), log (:17) and encode (:18) CITE
//! lines ride the replay verbatim — NEVER fake prints. The TB happy arm
//! (:16 pb=2048 lyr=14 next=35006 flags=4096) is the SIBLING-PAIR story:
//! a type-2 erspan ethertype (0x88BE = 35006) INSIDE a trans-bridge
//! frame, decimal-only.
//!
//! Ground truth #2: `tools/erspan_harness/vectors_faceA.txt` — the FACE-A
//! load/walk face (probe.cc, ONE probe x THREE hidden-BUILDING_SO tables;
//! the STATIC arms cd_erspan2/cd_erspan3/cd_transbridge EXIST nm-EXACTLY-1
//! each), 19 L md5 3ec325d785e92c75458d747d2ab70be2. THE trio mod_ctor
//! ASYMMETRY PIN replays here: erspan2 1/1 (REAL cc:102/:125-:126) +
//! erspan3 1/1 (REAL cc:104/:127-:128) vs trans_bridge 0/0 (EXPLICIT
//! nullptr pair :138/:139) — census 1/1/0 (contrast misc3's 1/0/0,
//! daq3's 1/1/1, miscip's 0/0: NO prior face carried). The LOAD face
//! :3 `LOAD trans_bridge` carries the name-drift story (drift TABLE
//! cd_transbridge, honest NAME string from the inside-anon-ns #define
//! :33). GETIDS 35006/8939/25944 DECIMAL (protocol_ids.h :159/:146/:147,
//! python-derived; :146 carries the ground TYPO `0X22EB` honesty pin).
//! The trio ladder names were ALREADY resident (codec_api.rs :103/:104/
//! :127) — this row TURNS them loaded as the tables land.

use snort3::codecs::cd_erspan2 as e2;
use snort3::codecs::cd_erspan3 as e3;
use snort3::codecs::cd_trans_bridge as tb;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/erspan_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/erspan_harness/vectors_faceA.txt");

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 18 lines, ordered,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored:
//    fixed buffers/fixtures copied EXACTLY from probe_dec.cc — z[4096]
//    zeros, the 0x20/0x10 nibble payloads, the 0x12 p[12] and 0x2E p[20]
//    happy fixtures, the 0xaa..0x88BE TB frame).
// ==========================================================================
#[test]
fn erspan_dec_transcript_replay() {
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

    let conf = SnortConfig::default();
    // probe's `extern const snort::BaseApi* cd_*[]` + ctor(nullptr):
    let ce2 = e2::Erspan2Codec::new(); // a2->ctor(nullptr)
    let ce3 = e3::Erspan3Codec::new(); // a3->ctor(nullptr)
    let ctb = tb::TransbridgeCodec::new(); // ab->ctor(nullptr)

    // ---- cd_erspan2: the two-event ladder (463 outer + shared 462) ----
    // vectors:1/:2 — z zeros len 7 < 8 (:79/:81 EV 463); lyr NEVER set.
    {
        let z = [0u8; 4096];
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        let b = ce2.decode(&raw, &mut cd, &mut sink); // bool var FIRST (R6)
        push(format!("E2 len7 -> {} lyr={}", b as i32, cd.lyr_len));
    }
    // vectors:3/:4 — p[8] 0x20 nibble: version 0x2 != 0x01 -> SHARED 462.
    {
        let p = [0x20, 0, 0, 0, 0, 0, 0, 0];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        let b = ce2.decode(&raw, &mut cd, &mut sink);
        push(format!("E2 v2-mismatch -> {} lyr={}", b as i32, cd.lyr_len));
    }
    // vectors:5 — p[12] 0x12 head: version 0x01 happy cc:93-:95 (lyr 8
    // BEFORE next 25944 — the order half of the :13 cite face).
    {
        let p = [0x12, 0x34, 0xAB, 0xCD, 0, 0, 0, 0, 0x08, 0x00, 0x11, 0x22];
        let raw = fw::RawData { data: &p, len: 12 };
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        let b = ce2.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "E2 happy -> {} lyr={} next={} flags={}",
            b as i32, cd.lyr_len, cd.next_prot_id, cd.codec_flags
        ));
    }
    // vectors:6 — the session-id CITE line (cc:61-:62 fields NEVER ported
    // beyond the >>12 mask — verbatim, NEVER a fake decode).
    push("E2 session-id cc:61-:62 ver_vlan+flags_spanId cited-never-ported face".to_string());

    // ---- cd_erspan3: 464 outer + shared 462 + the inverse order face ----
    // vectors:7/:8 — z len 19 < 20 (sizeof DISK face, §9) -> EV 464.
    {
        let z = [0u8; 4096];
        let raw = fw::RawData { data: &z, len: 19 };
        let mut cd = fw::CodecData::new(Some(&conf), e3::ETHERTYPE_ERSPAN_TYPE3);
        let b = ce3.decode(&raw, &mut cd, &mut sink);
        push(format!("E3 len19 -> {} lyr={}", b as i32, cd.lyr_len));
    }
    // vectors:9/:10 — p[20] 0x10 nibble: version 0x1 != 0x02 -> SHARED 462
    // (the EXACTLY-2 shared-462 census pair with :3).
    {
        let p = [0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let raw = fw::RawData { data: &p, len: 20 };
        let mut cd = fw::CodecData::new(Some(&conf), e3::ETHERTYPE_ERSPAN_TYPE3);
        let b = ce3.decode(&raw, &mut cd, &mut sink);
        push(format!("E3 v1-mismatch -> {} lyr={}", b as i32, cd.lyr_len));
    }
    // vectors:11 — p[20] 0x2E head: version 0x02 happy cc:95-:96 (NEXT
    // 25944 FIRST, lyr 20 SECOND — the inverse of E2, sizeof 20 face).
    {
        let p = [0x2E, 0x02, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3];
        let raw = fw::RawData { data: &p, len: 20 };
        let mut cd = fw::CodecData::new(Some(&conf), e3::ETHERTYPE_ERSPAN_TYPE3);
        let b = ce3.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "E3 happy -> {} lyr={} next={} flags={}",
            b as i32, cd.lyr_len, cd.next_prot_id, cd.codec_flags
        ));
    }
    // vectors:12/:13 — the session-id + order-site CITE lines verbatim.
    push("E3 session-id cc:60-:61 same-fields face cited-never-ported".to_string());
    push("E3 order-site next:95-before-lyr:96 vs E2 lyr:93-before-next:94 cite".to_string());

    // ---- cd_trans_bridge: the 165 arm + the eth-mirror happy arm ----
    // vectors:14/:15 — z len 13 < ETH_HEADER_LEN 14 -> EV 165 (the ONE
    // GRE token = the SID NAME only).
    {
        let z = [0u8; 4096];
        let raw = fw::RawData { data: &z, len: 13 };
        let mut cd = fw::CodecData::new(Some(&conf), tb::ETHERTYPE_TRANS_ETHER_BRIDGING);
        let b = ctb.decode(&raw, &mut cd, &mut sink);
        push(format!("TB len13 -> {}", b as i32));
    }
    // vectors:16 — dmac/smac + ethertype 0x88BE: the SIBLING-PAIR arm
    // pb=2048 lyr=14 next=35006 flags=4096 (cc:66-:69, the handshake).
    {
        let p = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x88, 0xBE];
        let raw = fw::RawData { data: &p, len: 14 };
        let mut cd = fw::CodecData::new(Some(&conf), tb::ETHERTYPE_TRANS_ETHER_BRIDGING);
        let b = ctb.decode(&raw, &mut cd, &mut sink);
        push(format!(
            "TB happy -> {} pb={} lyr={} next={} flags={}",
            b as i32, cd.proto_bits, cd.lyr_len, cd.next_prot_id, cd.codec_flags
        ));
    }
    // vectors:17/:18 — the log + encode CITE lines (cited-never-called,
    // NEVER fake log/encode prints through the transcript).
    push("TB log cc:83-:86 len-vs-type face cited-never-vectorized".to_string());
    push("TB encode cc:92/:98/:100-:109/:111-:112 cited-never-called EncState-IpApi face".to_string());

    let got = out.borrow();
    assert_eq!(got.len(), 18, "replay transcript length must equal the pinned face");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 19 lines (probe.cc in-probe
//    load_plugins witness walking the THREE hidden-BUILDING_SO tables
//    through the STATIC arms — cd_erspan2/cd_erspan3/cd_transbridge,
//    nm EXACTLY-1 each, the drift face incl).
// ==========================================================================
#[test]
fn erspan_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 19, "vectors_faceA.txt must hold the full 19-line walk");

    let mut got: Vec<String> = Vec::new();

    // the witness load face: for (; p && *p; ++p) printf("LOAD %s\n",
    // (*p)->name) — :3 `LOAD trans_bridge` = the drift TABLE carrying the
    // honest NAME string (inside-ns #define :33).
    for tab in [e2::CD_ERSPAN2, e3::CD_ERSPAN3, tb::CD_TRANSBRIDGE] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
    }
    got.push("LOADS 3".to_string());

    // probe.cc tabs[] = { cd_erspan2[0], cd_erspan3[0], cd_transbridge[0] }
    let tabs = [e2::CD_ERSPAN2, e3::CD_ERSPAN3, tb::CD_TRANSBRIDGE];
    let nm = ["erspan2", "erspan3", "trans_bridge"];
    for (tag, tab) in nm.iter().zip(tabs.iter()) {
        let a = tab[0];
        got.push(format!(
            "API {} type={} size={} ver={} name={}",
            tag, a.ptype, a.size, a.api_version, a.name
        ));
        got.push(format!("HELP {} {}", tag, a.help));
        // THE trio asymmetry PIN 1/1/0 (:7/:12/:17): erspan2 + erspan3
        // REAL mod pairs vs the trans_bridge nullptr pair :138/:139.
        got.push(format!(
            "{} mod_ctor={} mod_dtor={}",
            tag, a.mod_ctor as u8, a.mod_dtor as u8
        ));
        // ca->ctor(nullptr); ctor/dtor presence :8/:13/:18 (SET x3).
        got.push(format!("{} ctor={} dtor={}", tag, a.ctor as u8, a.dtor as u8));
        // c->get_protocol_ids(ids) — ALL THREE override (the trio's ONE
        // id each, DECIMAL): 35006 / 8939 / 25944.
        match *tag {
            "erspan2" => {
                let mut ids = Vec::new();
                e2::Erspan2Codec::new().get_protocol_ids(&mut ids);
                for id in ids {
                    got.push(format!("GETIDS {tag} {id}")); // 0x88BE = 35006
                }
            }
            "erspan3" => {
                let mut ids = Vec::new();
                e3::Erspan3Codec::new().get_protocol_ids(&mut ids);
                for id in ids {
                    got.push(format!("GETIDS {tag} {id}")); // 0X22EB typo-face = 8939
                }
            }
            _ => {
                let mut ids = Vec::new();
                tb::TransbridgeCodec::new().get_protocol_ids(&mut ids);
                for id in ids {
                    got.push(format!("GETIDS {tag} {id}")); // 0x6558 = 25944
                }
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
// 3. HIDDEN-TABLE tripwire + THE drift-name pins. The C tables live under
//    the hidden `#ifdef BUILDING_SO` split (sed-verbatim in build.sh EVERY
//    build): cd_erspan2.cc arm :139 feed :142 / cd_erspan3.cc arm :141
//    feed :144 / cd_trans_bridge.cc arm :152 feed :155 — the drift HEAD-
//    LINE name `cd_transbridge[]` (:152, the ONLY drift inside this row)
//    pins the Rust table const spelling CD_TRANSBRIDGE while the FILE
//    base stays cd_trans_bridge.rs (§5 discipline: a grep-vs-file
//    confusion trips LOUD at the harness sed pins, never at a file).
// ==========================================================================
#[test]
fn erspan_hidden_table_tripwire() {
    const E2_RS: &str = include_str!("../src/codecs/cd_erspan2.rs");
    const E3_RS: &str = include_str!("../src/codecs/cd_erspan3.rs");
    const TB_RS: &str = include_str!("../src/codecs/cd_trans_bridge.rs");
    // THE hidden-table NAME pins (cites cd_erspan2.cc:139 / cd_erspan3.
    // cc:141 / cd_trans_bridge.cc:152 static-arm statements — renaming a
    // const trips THIS assert; the daq3/small4/miscip drift posture):
    assert!(E2_RS.contains("pub const CD_ERSPAN2: CodecTable = &[&ERSPAN2_API];"),
        "the cd_erspan2 hidden-table const face drifted");
    assert!(E3_RS.contains("pub const CD_ERSPAN3: CodecTable = &[&ERSPAN3_API];"),
        "the cd_erspan3 hidden-table const face drifted");
    assert!(TB_RS.contains("pub const CD_TRANSBRIDGE: CodecTable = &[&TRANSBRIDGE_API];"),
        "the cd_transbridge drift-table const face drifted (const rides the TABLE spelling cc:152)");
    // the hidden-BUILDING_SO cite lines ride ALL THREE source faces:
    assert!(E2_RS.contains("const BaseApi*") && E2_RS.contains("cd_erspan2[]")); // cc:139 cite
    assert!(E3_RS.contains("const BaseApi*") && E3_RS.contains("cd_erspan3[]")); // cc:141 cite
    assert!(TB_RS.contains("const BaseApi*") && TB_RS.contains("cd_transbridge[]")); // cc:152 DRIFT cite
    // the file-vs-table drift HONESTY face (the 18l headline): the Rust
    // file carries the FILE base name in its own path cite while the
    // table cite rides the drift spelling (nm: the .o defines
    // cd_transbridge, EXACTLY-0 cd_trans_bridge — build.sh refuses):
    assert!(TB_RS.contains("cd_trans_bridge"));
    // ZERO #[no_mangle] in the trio (the src-wide landed pattern):
    assert!(!E2_RS.contains("#[no_mangle]"));
    assert!(!E3_RS.contains("#[no_mangle]"));
    assert!(!TB_RS.contains("#[no_mangle]"));
    // GRE cite-NEVER-LAND structural census (PLAN §3: cd_gre.rs stays a
    // CITE — the doc cites above name it honestly — but NEVER a LAND: no
    // use-import, no symbol reuse. The ONLY allowed coupling to the gre
    // family is sid 165 via the codec_module enum; ground-greps 0x3 every
    // build):
    for rs in [E2_RS, E3_RS, TB_RS] {
        assert!(!rs.contains("use crate::codecs::cd_gre"),
            "a cd_gre import landed — the §3 cite-NEVER-LAND ruling is dead");
        assert!(!rs.contains("cd_gre::"),
            "a cd_gre symbol landed — the §3 cite-NEVER-LAND ruling is dead");
    }
    // the cd_pppoepkt double-NAME belongs cd_pppoe.cc (18m) — NEVER this
    // row's erspair (the briefing wrong-on-disk face, §1/:18):
    assert!(!E2_RS.contains("cd_pppoepkt") && !E2_RS.contains("cd_pppencap"));
    assert!(!E3_RS.contains("cd_pppoepkt") && !E3_RS.contains("cd_pppencap"));

    // EXACTLY-1 entry per table == the `{ &*_api.base, nullptr }` C face
    // (harness walk loaded EXACTLY 3, faceA:4 `LOADS 3`):
    assert_eq!(e2::CD_ERSPAN2.len(), 1);
    assert_eq!(e3::CD_ERSPAN3.len(), 1);
    assert_eq!(tb::CD_TRANSBRIDGE.len(), 1);

    // feed identity (cc:142 / cc:144 / cc:155 feed &*_api.base):
    assert!(std::ptr::eq(e2::CD_ERSPAN2[0], &e2::ERSPAN2_API));
    assert!(std::ptr::eq(e3::CD_ERSPAN3[0], &e3::ERSPAN3_API));
    assert!(std::ptr::eq(tb::CD_TRANSBRIDGE[0], &tb::TRANSBRIDGE_API));

    // the ladder trio names RESIDENT (codec_api.rs :103/:104/:127 — the
    // DRIFT spelling "cd_transbridge" is what the ladder carries, the
    // ground extern codec_api.cc :69 / load :114 face; NEVER re-touched;
    // THIS row TURNS them loaded):
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_erspan2"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_erspan3"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_transbridge"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18l adds NO new externs"
    );

    // NAME side (the walk prints these words, faceA:5-:6/:10-:11/:15-:16;
    // the trans_bridge NAME rides the underscore INSIDE the drift table):
    assert_eq!(e2::CD_ERSPAN2_NAME, "erspan2");              // cc:29
    assert_eq!(e2::ERSPAN2_API.name, "erspan2");             // cc:123
    assert_eq!(e3::CD_ERSPAN3_NAME, "erspan3");              // cc:29
    assert_eq!(e3::ERSPAN3_API.name, "erspan3");             // cc:125
    assert_eq!(tb::CD_TRANSBRIDGE_NAME, "trans_bridge");     // cc:33 (inside ns :31-:32/:47)
    assert_eq!(tb::TRANSBRIDGE_API.name, "trans_bridge");    // cc:136
}

// ==========================================================================
// 4. THE record census + THE mod-arms asymmetry mirror 1/1/0: records x3
//    112/1900547/PT_CODEC + ctor/dtor SET + g/t nullptr x4 + the REAL
//    mod pairs (erspan2/erspan3) vs the nullptr pair (trans_bridge cc:
//    138/:139), and the RuleMap sibling-pair table ASYMMETRY (erspan2
//    TWO rows carrying the shared 462 FIRST, cc:36-:37; erspan3 ONE row
//    464 only, cc:36 — no 462 row despite cc:91 firing it).
// ==========================================================================
#[test]
fn erspan_record_census() {
    for a in [e2::ERSPAN2_API, e3::ERSPAN3_API, tb::TRANSBRIDGE_API] {
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
    // THE asymmetry PIN 1/1/0 (faceA:7/:12/:17): erspan2 mod_ctor() cc:102
    // + mod_dtor() cc:105 slots :125/:126; erspan3 cc:104/:107 slots :127/
    // :128; trans_bridge EXPLICIT nullptr pair :138/:139 (no comment).
    // Contrast misc3 1/0/0, daq3 1/1/1, miscip 0/0 — NOT carried. The
    // record fields ARE compile-time consts (the ext_parity_test.rs:587 /
    // small4_parity_test.rs:594 / misc3_parity_test.rs:486 assertion-
    // s_on_constants precedent — the cited point-site allow):
    #[allow(clippy::assertions_on_constants)] // pinned record-const face (lineage precedent, point-site)
    {
        assert!(e2::ERSPAN2_API.mod_ctor, "erspan2 mod_ctor MUST be the REAL arm (slots :125/:126)");
        assert!(e2::ERSPAN2_API.mod_dtor, "erspan2 mod_dtor MUST be the REAL arm");
        assert!(e3::ERSPAN3_API.mod_ctor, "erspan3 mod_ctor MUST be the REAL arm (slots :127/:128)");
        assert!(e3::ERSPAN3_API.mod_dtor, "erspan3 mod_dtor MUST be the REAL arm");
        assert!(!tb::TRANSBRIDGE_API.mod_ctor, "trans_bridge mod_ctor MUST be the nullptr arm :138");
        assert!(!tb::TRANSBRIDGE_API.mod_dtor, "trans_bridge mod_dtor MUST be the nullptr arm :139");
    }

    // the real-module faces (the 1/1 side): NAME/HELP land in the base.
    use snort3::codecs::codec_module as cm;
    let m2 = e2::Erspan2Module::new(); // cc:44 the 2-arg base ctor
    assert_eq!(m2.base.name, "erspan2");
    assert_eq!(m2.base.help, e2::CD_ERSPAN2_HELP);
    let m3 = e3::Erspan3Module::new(); // cc:43
    assert_eq!(m3.base.name, "erspan3");
    assert_eq!(m3.base.help, e3::CD_ERSPAN3_HELP);
    // trans_bridge: NO Module type exists (honest absence — grep-free
    // proof: the record pair above is false,false; the class cc:36-:46
    // derives Codec ONLY).

    // RuleMap census (the shared-462 table face §/31 pin re-measured):
    assert_eq!(cm::rule_count(&e2::ERSPAN2_RULES), 2, "erspan2 TWO rows + terminator cc:36-:38");
    assert_eq!(e2::ERSPAN2_RULES[0].sid, 462); // cc:36 the SHARED sid FIRST
    assert_eq!(e2::ERSPAN2_RULES[1].sid, 463); // cc:37
    assert_eq!(e2::ERSPAN2_RULES[2].sid, 0);   // cc:38 terminator
    assert_eq!(cm::rule_count(&e3::ERSPAN3_RULES), 1, "erspan3 ONE row + terminator cc:36-:37");
    assert_eq!(e3::ERSPAN3_RULES[0].sid, 464); // cc:36
    assert_eq!(e3::ERSPAN3_RULES[1].sid, 0);   // cc:37 terminator

    // sids RESIDENT (ZERO new consts, PLAN §4 — codec_module.rs arms
    // pinned by build.sh every build; the h-line cites):
    assert_eq!(cm::CodecSid::DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR as u32, 165); // :112, h:98
    assert_eq!(cm::CodecSid::DECODE_ERSPAN_HDR_VERSION_MISMATCH as u32, 462); // :220, h:215
    assert_eq!(cm::CodecSid::DECODE_ERSPAN2_DGRAM_LT_HDR as u32, 463);        // :221, h:216
    assert_eq!(cm::CodecSid::DECODE_ERSPAN3_DGRAM_LT_HDR as u32, 464);        // :222, h:217

    // HELP faces (faceA:6/:11/:16; the sed pins cc:30 / cc:30 / cc:34 —
    // the trans_bridge pair INSIDE the anon namespace :33-:34, the
    // enclosure pin §55 the RS file cites):
    assert_eq!(e2::ERSPAN2_API.help, "support for encapsulated remote switched port analyzer - type 2");
    assert_eq!(e3::ERSPAN3_API.help, "support for encapsulated remote switched port analyzer - type 3");
    assert_eq!(tb::TRANSBRIDGE_API.help, "support for trans-bridging");
}

// ==========================================================================
// 5. THE sids/shared-462 vector census + the cite-line + all-decimal
//    faces + the ground-typo honesty pin (`0X22EB`): pure text-census of
//    the pinned vectors + the three RS source faces (the harness greps
//    mirror, Rust-side).
// ==========================================================================
#[test]
fn erspan_sid_and_cite_census() {
    // EV census EXACTLY 5 lines, 4 DISTINCT sids == the §4 face:
    let evs: Vec<&str> = VECTORS.lines().filter(|l| l.starts_with("EV ")).collect();
    assert_eq!(evs.len(), 5, "463+462+464+462+165 (the harness grep face)");
    assert_eq!(
        evs.iter().map(|l| l.trim().to_string()).collect::<std::collections::BTreeSet<_>>(),
        ["EV 116 165".to_string(), "EV 116 462".to_string(), "EV 116 463".to_string(), "EV 116 464".to_string()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
    // THE shared-462 pin: EXACTLY-2 (the (a1) story — cc:89 + cc:91):
    assert_eq!(VECTORS.lines().filter(|l| *l == "EV 116 462").count(), 2, "462 rides BOTH siblings");
    // GID 116 on every EV line (GID_DECODE codec_module.h :38):
    assert!(evs.iter().all(|l| l.starts_with("EV 116 ")));
    // all-decimal hygiene (harness grep 0x face):
    assert!(!VECTORS.contains("0x"), "DEC face carries a hex literal");
    assert!(!VECTORS_FACE_A.contains("0x"), "FACE-A carries a hex literal");
    // the four CITE lines ride verbatim (session-id x2, order-site, log,
    // encode — the never-called faces):
    assert!(VECTORS.contains("session-id cc:61-:62 ver_vlan+flags_spanId cited-never-ported face"));
    assert!(VECTORS.contains("session-id cc:60-:61 same-fields face cited-never-ported"));
    assert!(VECTORS.contains("order-site next:95-before-lyr:96 vs E2 lyr:93-before-next:94 cite"));
    assert!(VECTORS.contains("log cc:83-:86 len-vs-type face cited-never-vectorized"));
    assert!(VECTORS.contains("encode cc:92/:98/:100-:109/:111-:112 cited-never-called EncState-IpApi face"));
    // ZERO tunnel/bypass face ANYWHERE (the §2 negative, both faces):
    for face in [VECTORS, VECTORS_FACE_A] {
        assert!(!face.contains("tunnel") && !face.contains("bypass"), "tunnel face crept into vectors");
    }
    // GETIDS trio DECIMAL faces (protocol_ids.h python-derived):
    assert!(VECTORS_FACE_A.contains("GETIDS erspan2 35006"));        // 0x88BE :159
    assert!(VECTORS_FACE_A.contains("GETIDS erspan3 8939"));         // 0X22EB :146 (typo face)
    assert!(VECTORS_FACE_A.contains("GETIDS trans_bridge 25944"));   // 0x6558 :147
    // the RS mirror of the ground TYPO honesty pin: the capital-X literal
    // `0X22EB` transcribed VERBATIM in the cite (NEVER silently fixed):
    const E3_RS: &str = include_str!("../src/codecs/cd_erspan3.rs");
    assert!(E3_RS.contains("0X22EB"), "the protocol_ids.h:146 ground typo face must ride verbatim");
    // sizeof-20 honesty pin (the §9 correction face rides the RS source):
    assert!(E3_RS.contains("ERSPAN3_HDR_SIZE: u32 = 20"));
}

// ==========================================================================
// 6. UNIT: the erspan version-gate ladders — boundary arms (len EXACTLY
//    8 / EXACTLY 20 the sizeof faces), the shared-462 both-siblings pair,
//    and the session-id NEVER-ported BEHAVIOR face (payloads differing
//    ONLY in the low-12 vlan bits decode IDENTICALLY — only the >>12
//    version nibble is extracted, cc:65-:66 / :68-:69).
// ==========================================================================
#[test]
fn up_erspan_version_gates() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));

    // erspan2 boundary: len EXACTLY 8 = sizeof(ERSpanType2Hdr) PASSES the
    // outer gate (a 0x01 nibble decodes); len 7 dies with 463.
    {
        let p = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        assert!(e2::Erspan2Codec::new().decode(&fw::RawData { data: &p, len: 8 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        assert_eq!((cd.lyr_len, cd.next_prot_id, cd.codec_flags), (8, 25944, 0)); // cc:93/:94
    }
    {
        let z = [0u8; 8];
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        assert!(!e2::Erspan2Codec::new().decode(&fw::RawData { data: &z, len: 7 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 463)]);
        assert_eq!(cd.lyr_len, 0, "fail path NEVER sets lyr (cc:82 return)");
    }
    // erspan2 mismatch arms (ALL version nibbles != 0x01 -> SHARED 462):
    for nib in [0x0u8, 0x2, 0x7, 0xF] {
        let p = [nib << 4, 0, 0, 0, 0, 0, 0, 0];
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        assert!(!e2::Erspan2Codec::new().decode(&fw::RawData { data: &p, len: 8 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 462)], "nibble {nib:#x} arm");
    }
    // erspan3 boundary: len EXACTLY 20 = sizeof(ERSpanType3Hdr) (the §9
    // DISK face) PASSES; len 19 dies with 464.
    {
        let p = [0x20u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut cd = fw::CodecData::new(Some(&conf), e3::ETHERTYPE_ERSPAN_TYPE3);
        assert!(e3::Erspan3Codec::new().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        assert_eq!((cd.lyr_len, cd.next_prot_id, cd.codec_flags), (20, 25944, 0)); // cc:95/:96 NEXT-FIRST
    }
    {
        let z = [0u8; 20];
        let mut cd = fw::CodecData::new(Some(&conf), e3::ETHERTYPE_ERSPAN_TYPE3);
        assert!(!e3::Erspan3Codec::new().decode(&fw::RawData { data: &z, len: 19 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 464)]);
        assert_eq!(cd.lyr_len, 0, "fail path NEVER sets lyr (cc:85 return)");
    }
    // erspan3 mismatch arms (ALL version nibbles != 0x02 -> SHARED 462 —
    // the EXACTLY-2 shared census unit-mirror):
    for nib in [0x0u8, 0x1, 0x3, 0xF] {
        let p = [nib << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut cd = fw::CodecData::new(Some(&conf), e3::ETHERTYPE_ERSPAN_TYPE3);
        assert!(!e3::Erspan3Codec::new().decode(&fw::RawData { data: &p, len: 20 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 462)], "nibble {nib:#x} arm");
    }
    // SESSION-ID never-ported BEHAVIOR face: the low-12 ver_vlan bits +
    // the WHOLE flags_spanId field NEVER affect the decode — the ONLY
    // extracted field is the >>12 version (cc:61-:62 cited, NEVER ported):
    for p in [
        [0x12u8, 0x34, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00], // vectors fixture head (vlan 0x234)
        [0x10u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // vlan 0 face
        [0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],   // vlan+spanId maxed
    ] {
        let mut cd = fw::CodecData::new(Some(&conf), e2::ETHERTYPE_ERSPAN_TYPE2);
        assert!(e2::Erspan2Codec::new().decode(&fw::RawData { data: &p, len: 8 }, &mut cd, &mut sink));
        assert_eq!((cd.lyr_len, cd.next_prot_id), (8, 25944), "identical decode across vlan/spanId faces");
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
    }
}

// ==========================================================================
// 7. UNIT: the TB decode/log/encode mirror. The vectors NEVER call log/
//    encode (cite lines :17/:18) — these units pin the ported-by-reading
//    code faces (the eth parity test mirrors its encode the same way).
// ==========================================================================
#[test]
fn up_trans_bridge_arms() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = tb::TransbridgeCodec::new();

    // decode boundary: len EXACTLY 14 = ETH_HEADER_LEN passes; 13 dies 165.
    {
        let p = [0u8; 14];
        let mut cd = fw::CodecData::new(Some(&conf), tb::ETHERTYPE_TRANS_ETHER_BRIDGING);
        assert!(c.decode(&fw::RawData { data: &p, len: 14 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        // the EVAL ORDER: the :2048/:14/:0-ethertype/:4096 writes ALL land
        // in cc:66-:69 order (the pair story with the ethertype from OURS):
        assert_eq!((cd.proto_bits, cd.lyr_len, cd.next_prot_id, cd.codec_flags), (2048, 14, 0, 4096));
    }
    {
        let mut cd = fw::CodecData::new(Some(&conf), tb::ETHERTYPE_TRANS_ETHER_BRIDGING);
        assert!(!c.decode(&fw::RawData { data: &[0u8; 14], len: 13 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 165)]); // cc:54/:56
    }
    // the pair handshake face: the probe TB fixture (0x88BE inner) ->
    // next 35006 == the erspan2 id (the sibling story, cross-file parity):
    {
        let p = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x88, 0xBE];
        let mut cd = fw::CodecData::new(Some(&conf), tb::ETHERTYPE_TRANS_ETHER_BRIDGING);
        assert!(c.decode(&fw::RawData { data: &p, len: 14 }, &mut cd, &mut sink));
        assert_eq!(cd.next_prot_id, 35006);
        assert_eq!(cd.next_prot_id, e2::ETHERTYPE_ERSPAN_TYPE2); // the pair pin (both u16)
    }

    // log face cc:83-:86 (cited-never-vectorized; the sink-capture mirror,
    // the cd_eth rs:193-:198 posture — LogEthAddrs the silent stand-in):
    let log = |pkt: [u8; 14]| -> String {
        let mut lines = Vec::new();
        c.log(&mut |s: String| lines.push(s), &pkt, 14);
        assert_eq!(lines.len(), 1, "one TextLog_Print fragment (cc:84/:86 arms)");
        lines.remove(0)
    };
    let mut lo = [0u8; 14];
    lo[12..14].copy_from_slice(&0x0107u16.to_be_bytes()); // ETHERNET_LLC <= MINIMUM -> len:
    assert_eq!(log(lo), "  len:0x0107"); // the <= ETHERTYPE_MINIMUM arm
    let mut eqmin = [0u8; 14];
    eqmin[12..14].copy_from_slice(&0x0600u16.to_be_bytes()); // EXACTLY MINIMUM (<=, cc:83)
    assert_eq!(log(eqmin), "  len:0x0600");
    let mut hi = [0u8; 14];
    hi[12..14].copy_from_slice(&0x88BEu16.to_be_bytes()); // > MINIMUM -> type:
    assert_eq!(log(hi), "  type:0x88BE"); // %04X upper-case (cc:86)

    // encode face cc:92-:114 (cited-never-CALLED by the vectors; unit-
    // mirrored like the eth row): allocate -> ethertype-select -> keep/
    // swap -> NOT_SET resets.
    let hi_frame = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0x65, 0x58];
    // (a) ethertype_set TRUE + forward: enc.next_ethertype wins, MACs kept.
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        enc.next_ethertype = 0x0800; // ethertype_set() TRUE (enc.rs:306 face)
        assert!(c.encode(&hi_frame, 14, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(14) just succeeded");
        assert_eq!(&out[0..6], &hi_frame[0..6]);  // cc:102 dst<-dst
        assert_eq!(&out[6..12], &hi_frame[6..12]); // cc:103 src<-src
        assert_eq!(&out[12..14], &[0x08, 0x00]);   // cc:98 htons(next) wire bytes
        assert_eq!(enc.next_ethertype, tb_fw_not_set()); // cc:111 reset
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET); // cc:112
    }
    // (b) ethertype_set FALSE + reverse: hi wire copy + MAC SWAP.
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0); // NOT forward (ENC_FLAG_FWD absent)
        assert!(c.encode(&hi_frame, 14, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(14) just succeeded");
        assert_eq!(&out[0..6], &hi_frame[6..12]); // cc:107 dst<-SRC
        assert_eq!(&out[6..12], &hi_frame[0..6]); // cc:108 src<-DST
        assert_eq!(&out[12..14], &[0x65, 0x58]);  // cc:98 FALSE arm (hi wire)
        assert_eq!(enc.next_ethertype, tb_fw_not_set());
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET);
    }

    // the twin-parity + import faces (dup-not-import ruling, cites):
    use snort3::codecs::cd_eth as ethc;
    assert_eq!(tb::ETH_HEADER_LEN, ethc::ETH_HEADER_LEN); // eth.h:37 x2 homes
    assert_eq!(tb::ETHERTYPE_TRANS_ETHER_BRIDGING, e2::ETHERTYPE_TRANS_ETHER_BRIDGING); // :147 twins
    assert_eq!(tb::ETHERTYPE_TRANS_ETHER_BRIDGING, e3::ETHERTYPE_TRANS_ETHER_BRIDGING); // :147 twins
    assert_eq!(fw::PROTO_BIT__ETH, 2048);  // decode_data.h:98 IMPORT (vectors pb)
    assert_eq!(fw::CODEC_ETHER_NEXT, 4096); // codec.h IMPORT (vectors flags)
    assert_eq!(fw::protocol_id::ETHERTYPE_MINIMUM, 0x0600); // :143 (the log gate import)
}

/// protocol_id::ETHERTYPE_NOT_SET via the framework import (cc:111 face).
fn tb_fw_not_set() -> u16 {
    fw::protocol_id::ETHERTYPE_NOT_SET
}
