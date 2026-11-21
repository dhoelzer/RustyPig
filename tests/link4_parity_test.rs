//! Parity test for the row-18n codecs/link vlan TRIO ports — three ground
//! TUs (link/cd_vlan.cc 236 L md5 fe9747e87a7383eeacf43ce381b5ab7c /
//! link/cd_ciscometadata.cc 235 L md5 8cd594aa2a6576c56ea0136b1b2bdc05 /
//! link/cd_fabricpath.cc 187 L md5 f3fee8d9caf01be7686c9d1907e8f18b; wc
//! 236/235/187 + the 658 SUM re-measured and asserted EVERY build by
//! tools/link4_harness/build.sh). ZERO-gate row (21st straight honest
//! face): find src/codecs/link -type d -name test = 0 + add_cpputest
//! census 0 -> NO up_gate_* set: honest absence, census-cited (PLAN §0).
//!
//! Ground truth #1: `tools/link4_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 28 L md5 c7f5808fa326b7831603813c16a3b01e NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session (per-index assert_eq over want.len()==28). THE R6 EVAL-ORDER
//! RULE REPLAYS: every decode bool lands in a var BEFORE the summary
//! line and every `EV 116 <sid>` lands between the decode call and its
//! printf, NEVER sorted. THE graft-v3 ORDER PIN rides INSIDE the walk:
//! line 6 `V vid0-ignore` carries NO preceding EV (the :143 short-circuit
//! skips BOTH the :145-:148 event AND the :150 pb set — pb=0), while
//! line 7 `EV 116 130` precedes line 8 `V vid0` (same bytes, flag OFF —
//! pb=1024): the interleave IS the pin (PLAN §8, the ext is NOT
//! decorative). EV census 8 lines / 6 distinct sids {130x3,467,468,469,
//! 470,471} — the sids ride codec_module.rs :96/:225-:229.
//!
//! Ground truth #2: `tools/link4_harness/vectors_faceA.txt` — the FACE-A
//! load/walk face (probe.cc over the THREE hidden-BUILDING_SO TRUE-NAME
//! tables), 24 L md5 9fdfc50da8fee22b473028f1f9b29c12. ONE LOAD line per
//! table + LOADS 1 x3 (the 18m double-NAME contrast). mod arms REAL x3
//! (1/1 — the nullptr-free tail face, NEVER carried from 18m/18l). GETIDS
//! DECIMAL: vlan rides the unordered-SET face (id_set cd_vlan.cc :103 —
//! the four ids {33024, 34984, 37120, 37376} assert as a SET, the
//! libstdc++ bucket print order NEVER pinned, PLAN §8 caution honored:
//! the ordered replay pins the BLOCK as sorted-equal + each id present
//! exactly once); ciscometadata 35081, fabricpath 35075.
//!
//! THE MPLS NEVER-LAND negative census (PLAN §3/q4 deferred-row law):
//! grep-0 mpls/MPLS tokens ACROSS the trio rs files + BOTH vectors — the
//! deferred TU NEVER leaks a sid, a hook, or a name into this row.

use snort3::codecs::cd_ciscometadata as cm;
use snort3::codecs::cd_fabricpath as fp;
use snort3::codecs::cd_vlan as vl;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/link4_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/link4_harness/vectors_faceA.txt");

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 28 lines, ORDERED,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored;
//    fixtures copied EXACTLY from probe_dec.cc: the z[4096] zeros, the
//    {0x00,0x0A,0x08,0x00} vlan fixtures, the 0x00C8 LLC + 0x88A8 QinQ
//    protos, the {0x0F,0xFF,...} vid4095 fixture, the 8-byte cisco
//    fixtures {01,01,00,01,...} ladder family). THE witness-pkthdr seam
//    (harness witness_pkthdr.cc pkthdr_witness_set_flags face) lands as
//    the decode's pkthdr_flags param: EXACTLY the V5 arm (line 6) rides
//    0x40, every other arm 0 — the probe toggles the SAME observable.
// ==========================================================================
#[test]
fn link4_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 28, "vectors.txt must hold the full 28-line DEC ladder");

    use std::cell::RefCell;
    use std::rc::Rc;
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let push = {
        let out = Rc::clone(&out);
        move |s: String| out.borrow_mut().push(s)
    };
    // the queue_event witness seam: `EV %u %u` (GID_DECODE 116, stubs_18d
    // carried face — queue_event prints, NEVER re-walked).
    let mut sink = {
        let out = Rc::clone(&out);
        move |gid: u32, sid: u32| out.borrow_mut().push(format!("EV {gid} {sid}"))
    };

    let conf = SnortConfig::default();
    // the probe's ctor faces: av->ctor(nullptr)/af->ctor(nullptr)/ac->
    // ctor(nullptr) off the THREE tables; the nullptr-mod arm (:200
    // `mod ? mod->get_tpids() : default_tpids`) lands VlanCodec::new
    // (DEFAULT_TPIDS window — the faceA SET face's tpids leg).
    let cv = vl::VlanCodec::new(vl::DEFAULT_TPIDS.to_string()); // :197-:201 nullptr-mod face
    let cf = fp::FabricPathCodec::new(); // :150 ctor (Module* DISCARDED)
    let cc = cm::CiscoMetaDataCodec::new(); // :199 ctor (Module* DISCARDED twin)

    let z = [0u8; 4096]; // probe's `uint8_t z[4096]={0}`

    // ---- vlan ----
    // vectors:1/:2 — len3 < 4 (:120) -> EV 130 (:122); lyr NEVER set (:123).
    {
        let raw = fw::RawData { data: &z, len: 3 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, 0); // bool var FIRST (R6)
        push(format!("V len3 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:3 — vid 10 / proto 0x0800: lyr 4 (:139), next 2048 CAST face
    // (:137), flag OFF -> :147 passes (:148 SKIPPED), :150 pb 1024.
    {
        let p = [0x00u8, 0x0A, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, 0);
        push(format!(
            "V ok -> {} lyr={} next={} pb={}",
            b as i32, cdd.lyr_len, cdd.next_prot_id, cdd.proto_bits
        ));
    }
    // vectors:4 — proto 0x00C8 (200 <= 1518 :98) -> ETHERNET_LLC 263 (:135).
    {
        let p = [0x00u8, 0x0A, 0x00, 0xC8];
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, 0);
        push(format!("V llc -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:5 — QinQ 0x88A8 pass-through: the CAST at :137 rides (34984).
    {
        let p = [0x00u8, 0x0A, 0x88, 0xA8];
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, 0);
        push(format!("V qinq -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:6 — THE graft-v3 ext arm: vid 0 bytes, IGNORE_VLAN flag ON
    // (witness 0x40). :142->:143 return TRUE BEFORE :145-:148: NO EV 130
    // rides AND pb STAYS 0 (:150 never reached). NO EV line precedes this
    // print in the vectors — the transcript interleave IS the proof.
    {
        let p = [0x00u8, 0x00, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, vl::DAQ_PKT_FLAG_IGNORE_VLAN);
        push(format!(
            "V vid0-ignore -> {} lyr={} next={} pb={}",
            b as i32, cdd.lyr_len, cdd.next_prot_id, cdd.proto_bits
        ));
    }
    // vectors:7/:8 — SAME bytes, flag OFF: EV 130 (:148) lands BETWEEN the
    // decode and the print; :150 then sets pb 1024 — the V5/V6 CONTRAST.
    {
        let p = [0x00u8, 0x00, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, 0);
        push(format!("V vid0 -> {} lyr={} pb={}", b as i32, cdd.lyr_len, cdd.proto_bits));
    }
    // vectors:9/:10 — vid 4095 upper reserved arm (:147).
    {
        let p = [0x0Fu8, 0xFF, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 4 };
        let mut cdd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        let b = cv.decode(&raw, &mut cdd, &mut sink, 0);
        push(format!("V vid4095 -> {} lyr={} pb={}", b as i32, cdd.lyr_len, cdd.proto_bits));
    }
    // vectors:11 — the order-site + encode/log CITE line (verbatim).
    push("V order-site ext:141->143-before-badvid:145->148 pb0-vs-1024 cite; V encode cc:173-:185 + V log cc:154-:171 cited-never-called".to_string());

    // ---- fabricpath ----
    // vectors:12/:13 — len15 < 16 (:78) -> EV 467 (:80); lyr NEVER set.
    {
        let raw = fw::RawData { data: &z, len: 15 };
        let mut cdd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_FPATH);
        let b = cf.decode(&raw, &mut cdd, &mut sink);
        push(format!("F len15 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:14 — len16: next 261 (:84) BEFORE lyr 16 (:85) — the print
    // order pins the R6 NEXT-FIRST clone.
    {
        let raw = fw::RawData { data: &z, len: 16 };
        let mut cdd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_FPATH);
        let b = cf.decode(&raw, &mut cdd, &mut sink);
        push(format!("F len16 -> {} next={} lyr={}", b as i32, cdd.next_prot_id, cdd.lyr_len));
    }
    // vectors:15 — the order-site + encode/format CITE line (verbatim).
    push("F order-site next:84-before-lyr:85 cite; F encode cc:89-:125 + F format cc:127-:137 cited-never-called".to_string());

    // ---- ciscometadata ----
    // vectors:16/:17 — len7 < 8 (:106) -> stats cite (:108, cite-never-
    // land) + EV 468 (:109); lyr NEVER set.
    {
        let raw = fw::RawData { data: &z, len: 7 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!("C len7 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:18 — version 0: SILENT stats-only fail (:116-:120) — NO EV
    // line rides (the census-pinned silent-fail arm).
    {
        let p = [0x00u8, 1, 0x00, 0x01, 0x00, 0x2A, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!("C ver0 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:19 — length 0: SILENT again (:122-:126).
    {
        let p = [0x01u8, 0, 0x00, 0x01, 0x00, 0x2A, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!("C lenf0 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:20/:21 — opt_len 0x2001 >> 13 == 1 > 0 (:134) -> EV 469.
    {
        let p = [0x01u8, 1, 0x20, 0x01, 0x00, 0x2A, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!("C optlen1 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:22/:23 — type 0x0002 != SGT 1 (:141) -> EV 470.
    {
        let p = [0x01u8, 1, 0x00, 0x02, 0x00, 0x2A, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!("C opttype2 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:24/:25 — sgt 0xFFFF: SOFT EV 471 (:152) then CONTINUES —
    // the full tail face: lyr 8 (:155) next 2048 CAST (:157) flags 4096
    // CODEC_ETHER_NEXT (:159) pb 131072 (:160).
    {
        let p = [0x01u8, 1, 0x00, 0x01, 0xFF, 0xFF, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!(
            "C sgtffff -> {} lyr={} next={} flags={} pb={}",
            b as i32, cdd.lyr_len, cdd.next_prot_id, cdd.codec_flags, cdd.proto_bits
        ));
    }
    // vectors:26 — CLEAN sgt 42: NO event, SAME tail face.
    {
        let p = [0x01u8, 1, 0x00, 0x01, 0x00, 0x2A, 0x08, 0x00];
        let raw = fw::RawData { data: &p, len: 8 };
        let mut cdd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        let b = cc.decode(&raw, &mut cdd, &mut sink);
        push(format!(
            "C clean -> {} lyr={} next={} flags={} pb={}",
            b as i32, cdd.lyr_len, cdd.next_prot_id, cdd.codec_flags, cdd.proto_bits
        ));
    }
    // vectors:27/:28 — the two CITE lines (verbatim; the pegs face the
    // probe prints instead of vectorizing counts).
    push("C order-site ver:116-len:122-opt:130-type:141-sgt:149-lyr:155 cite; C pegs cc:49-:59 CountType-END:53 cited-not-vectorized".to_string());
    push("C encode cc:175-:187 + C log cc:165-:173 cited-never-called".to_string());

    let got = out.borrow();
    assert_eq!(got.len(), 28, "replay transcript length must equal the pinned face");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 24 lines (probe.cc in-probe
//    PluginManager::load_plugins witness over the THREE TRUE-NAME tables;
//    ONE LOAD line each + LOADS 1 — the 18m double-LOAD contrast). THE
//    vlan GETIDS block (lines 11-14) rides the UNORDERED-SET face: the
//    probe's PRINT order is the harness runner's bucket walk, NEVER a
//    port fact (PLAN §8) — pinned as sorted-equal SET + per-id EXACTLY-
//    once (the block boundary itself stays positional: exactly the four
//    `GETIDS vlan ` lines).
// ==========================================================================
#[test]
fn link4_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 24, "vectors_faceA.txt must hold the full 24-line walk");

    let mut got: Vec<String> = Vec::new();

    // witness load face probe.cc:42-43 + the probe's explicit per-table
    // counts: ONE walk prints ONE LOAD line; LOADS 1 x3 (feeds :234/:233/
    // :184 — three single-entry tables).
    for tab in [vl::CD_VLAN, cm::CD_CISCOMETADATA, fp::CD_FABRICPATH] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
        got.push(format!("LOADS {}", tab.len()));
    }

    // probe.cc tabs[3] = { cd_vlan[0], cd_ciscometadata[0], cd_fabricpath[0] }
    let tabs = [
        (vl::CD_VLAN[0], "vlan"),
        (cm::CD_CISCOMETADATA[0], "ciscometadata"),
        (fp::CD_FABRICPATH[0], "fabricpath"),
    ];
    for (a, tag) in tabs {
        got.push(format!(
            "API {} type={} size={} ver={} name={}",
            tag, a.ptype, a.size, a.api_version, a.name
        ));
        got.push(format!("HELP {} {}", tag, a.help));
        // THE mod-arms face MEASURED x3 REAL (NEVER carried): vlan arms
        // :217/:218, cisco :216/:217, fabricpath :167/:168 — the trio's
        // nullptr-FREE face (contrast 18m's pppencap pair, 18l's TB pair).
        got.push(format!("{} mod_ctor={} mod_dtor={}", tag, a.mod_ctor as u8, a.mod_dtor as u8));
        // ca->ctor(nullptr): ctor/dtor SET x3 (:224/:225, :223/:224,
        // :174/:175) — vlan :200 nullptr-mod -> DEFAULT_TPIDS window.
        got.push(format!("{} ctor={} dtor={}", tag, a.ctor as u8, a.dtor as u8));
        // c->get_protocol_ids(ids) -> GETIDS DECIMAL.
        match tag {
            "vlan" => {
                let mut ids = Vec::new();
                vl::VlanCodec::new(vl::DEFAULT_TPIDS.to_string()).get_protocol_ids(&mut ids);
                for id in ids { got.push(format!("GETIDS {tag} {id}")); }
            }
            "ciscometadata" => {
                let mut ids = Vec::new();
                cm::CiscoMetaDataCodec::new().get_protocol_ids(&mut ids);
                for id in ids { got.push(format!("GETIDS {tag} {id}")); }
            }
            _ => {
                let mut ids = Vec::new();
                fp::FabricPathCodec::new().get_protocol_ids(&mut ids);
                for id in ids { got.push(format!("GETIDS {tag} {id}")); }
            }
        }
        // ca->dtor(c): the stack-owned Rust fold (18d posture), silent.
    }

    assert_eq!(got.len(), 24);
    // ordered compare EVERYWHERE EXCEPT the unordered-SET block — the
    // four vlan GETIDS lines (want:11-14) replay as a SET (sorted), the
    // bucket order NEVER pinned (PLAN §8; the id_set :103 face).
    let vl_block_want: Vec<String> = want[10..14].iter().map(|s| s.to_string()).collect();
    let vl_block_got: Vec<String> = got[10..14].to_vec();
    for (i, range) in [(0usize, 10usize), (14, 24)] {
        for j in i..range {
            assert_eq!(got[j], want[j], "faceA line {}: replay {:?} != measured {:?}", j + 1, got[j], want[j]);
        }
    }
    for l in &vl_block_got {
        assert!(l.starts_with("GETIDS vlan "), "the vlan GETIDS block boundary drifted: {l:?}");
    }
    let mut a = vl_block_got.clone();
    let mut b = vl_block_want.clone();
    a.sort();
    b.sort();
    assert_eq!(a, b, "the vlan GETIDS SET face drifted (unordered_set :103 — the SET pins, NEVER the walk)");
    // the SET itself (protocol_ids.h :149/:158 + tpids :49 0x9100/0x9200):
    assert_eq!(
        vl_block_want,
        ["GETIDS vlan 37120", "GETIDS vlan 37376", "GETIDS vlan 34984", "GETIDS vlan 33024"],
        "the pinned SET block drifted"
    );
}

// ==========================================================================
// 3. TRUE-NAME triple tripwires (the 18m drift CONTRAST: all THREE tables
//    == file bases; cd_vlan[] :231 / cd_ciscometadata[] :230 /
//    cd_fabricpath[] :181 — the nm D-face EQUALITY pins ride build.sh;
//    Rust-side mirror: the consts ride the FILE bases, table-vs-file NAME
//    faces per PLAN §9 name-pin census). Ladder RESIDENT codec_api.rs
//    :101/:107/:130 (ground externs codec_api.cc :43/:49/:72 + loads :88/
//    :94/:117) NEVER re-touched — THIS row TURNS them loaded.
// ==========================================================================
#[test]
fn link4_true_name_tripwire() {
    const V_RS: &str = include_str!("../src/codecs/cd_vlan.rs");
    const C_RS: &str = include_str!("../src/codecs/cd_ciscometadata.rs");
    const F_RS: &str = include_str!("../src/codecs/cd_fabricpath.rs");
    // the table consts pin EXACTLY (single-feed tables):
    assert!(
        V_RS.contains("pub const CD_VLAN: CodecTable = &[&VLAN_API];"),
        "the cd_vlan TRUE-NAME table const drifted (:231, feed :234)"
    );
    assert!(
        C_RS.contains("pub const CD_CISCOMETADATA: CodecTable = &[&CISCOMETADATA_API];"),
        "the cd_ciscometadata TRUE-NAME table const drifted (:230, feed :233)"
    );
    assert!(
        F_RS.contains("pub const CD_FABRICPATH: CodecTable = &[&FABRICPATH_API];"),
        "the cd_fabricpath TRUE-NAME table const drifted (:181, feed :184)"
    );
    // the hidden-BUILDING_SO cite lines ride all THREE source faces:
    assert!(V_RS.contains("const BaseApi* cd_vlan[] =") || V_RS.contains("`const BaseApi* cd_vlan[] =`")); // :231 cite
    assert!(C_RS.contains("const BaseApi* cd_ciscometadata[] =") || C_RS.contains("`const BaseApi* cd_ciscometadata[] =`")); // :230 cite
    assert!(F_RS.contains("const BaseApi* cd_fabricpath[] =") || F_RS.contains("`const BaseApi* cd_fabricpath[] =`")); // :181 cite
    // TRUE-NAME face: table spelling == file base (the 18m drift CONTRAST
    // has NOTHING to refuse HERE — the equalities ARE the pin):
    for rs in [V_RS, C_RS, F_RS] {
        assert!(!rs.contains("#[no_mangle]"), "the src-wide landed pattern: ZERO no_mangle");
    }
    // the file bases ride their landing files (the honesty face):
    assert!(V_RS.contains("cd_vlan.cc") && V_RS.contains("cd_vlan.rs"));
    assert!(C_RS.contains("cd_ciscometadata.cc") && C_RS.contains("cd_ciscometadata.rs"));
    assert!(F_RS.contains("cd_fabricpath.cc") && F_RS.contains("cd_fabricpath.rs"));
    // ladder RESIDENT (codec_api.rs :101/:107/:130) — NEVER re-walked:
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_ciscometadata"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_fabricpath"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_vlan"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18n adds NO new externs"
    );
    // NAME macros (faceA name pins):
    assert_eq!(vl::CD_VLAN[0].name, "vlan");               // :38
    assert_eq!(cm::CD_CISCOMETADATA[0].name, "ciscometadata"); // :31
    assert_eq!(fp::CD_FABRICPATH[0].name, "fabricpath");   // :29
    // feed identity (single-feed x3):
    assert!(std::ptr::eq(vl::CD_VLAN[0], &vl::VLAN_API));               // &vlan_api.base :234
    assert!(std::ptr::eq(cm::CD_CISCOMETADATA[0], &cm::CISCOMETADATA_API)); // :233
    assert!(std::ptr::eq(fp::CD_FABRICPATH[0], &fp::FABRICPATH_API));  // :184
}

// ==========================================================================
// 4. THE record census: THREE records 112/1900547/PT_CODEC, ctor/dtor SET
//    x3, g/t nullptr x3 x4, and the mod arms MEASURED REAL x3 (1/1 x3 —
//    vlan :217/:218, cisco :216/:217, fabricpath :167/:168; the trio =
//    the nullptr-FREE tail face, NO prior row's pair carried). THE RuleMap
//    census: 1+term / 4+term / 1+term rows, msgs byte-exact. THE sids SIX
//    DISTINCT RESIDENT face {130 :96, 467 :225, 468-471 :226-:229} — ZERO
//    new consts (PLAN §1 6/6 resident census).
// ==========================================================================
#[test]
fn link4_record_census() {
    for a in [vl::VLAN_API, cm::CISCOMETADATA_API, fp::FABRICPATH_API] {
        assert_eq!(a.ptype, fw::PT_CODEC);          // :209/:208/:159
        assert_eq!(a.size, 112);                    // sizeof(CodecApi), faceA x3
        assert_eq!(a.api_version, 1900547);         // faceA ver pin x3
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
    // THE mod-arms MEASURED x3 REAL (faceA :9/:17/:22 — the nullptr-free
    // trio face; compile-time record consts, the ext/small4/misc3/erspan/
    // link6 assertions_on_constants lineage precedent, point-site allow):
    #[allow(clippy::assertions_on_constants)] // pinned record-const face (lineage precedent, point-site)
    {
        assert!(vl::VLAN_API.mod_ctor && vl::VLAN_API.mod_dtor, "vlan arms REAL (:191/:194 -> :217/:218)");
        assert!(cm::CISCOMETADATA_API.mod_ctor && cm::CISCOMETADATA_API.mod_dtor, "cisco arms REAL (:193/:196 -> :216/:217)");
        assert!(fp::FABRICPATH_API.mod_ctor && fp::FABRICPATH_API.mod_dtor, "fabricpath arms REAL (:144/:147 -> :167/:168)");
    }

    // module faces: THREE real Modules (contrast 18m's pppencap honest
    // absence — every trio member owns a Module):
    use snort3::codecs::codec_module as cmmod;
    let mv = vl::VlanModule::new();
    assert_eq!(mv.base.name, "vlan");
    assert_eq!(mv.base.help, vl::CD_VLAN_HELP);
    assert_eq!(cmmod::rule_count(mv.get_rules()), 1); // :45 (ONE row before :46)
    // THE vlan params face (the trio's ONLY Parameter table — :51-:57,
    // the esp params-landed precedent): PT_INT_LIST + the default_tpids:
    assert_eq!(vl::VLAN_PARAMS.len(), 2);
    assert_eq!(vl::VLAN_PARAMS[0].name, Some("extra_tpid_ether_types")); // :53
    assert_eq!(vl::VLAN_PARAMS[0].ptype, snort3::framework::parameter::Type::PtIntList); // :53
    assert_eq!(vl::VLAN_PARAMS[0].deflt, Some(vl::DEFAULT_TPIDS)); // :53
    let mc = cm::CiscoMetaDataModule::new();
    assert_eq!(mc.base.name, "ciscometadata");
    assert_eq!(cmmod::rule_count(mc.get_rules()), 4); // :38-:41 FOUR rows
    let mf = fp::FabricPathModule::new();
    assert_eq!(mf.base.name, "fabricpath");
    assert_eq!(cmmod::rule_count(mf.get_rules()), 1); // :36

    // RuleMap census + byte-exact msgs:
    assert_eq!(vl::VLAN_RULES[0].sid, 130);
    assert_eq!(vl::VLAN_RULES[0].msg, Some("bad VLAN frame")); // :45
    assert_eq!(vl::VLAN_RULES[1].sid, 0);
    assert_eq!(vl::VLAN_RULES.len(), 2);
    assert_eq!(cm::CISCOMETADATA_RULES[0].sid, 468);
    assert_eq!(cm::CISCOMETADATA_RULES[0].msg, Some("truncated Cisco Metadata header")); // :38
    assert_eq!(cm::CISCOMETADATA_RULES[1].msg, Some("invalid Cisco Metadata option length")); // :39
    assert_eq!(cm::CISCOMETADATA_RULES[2].msg, Some("invalid Cisco Metadata option type")); // :40
    assert_eq!(cm::CISCOMETADATA_RULES[3].msg, Some("invalid Cisco Metadata security group tag")); // :41
    assert_eq!(cm::CISCOMETADATA_RULES[4].sid, 0);
    assert_eq!(cm::CISCOMETADATA_RULES.len(), 5);
    assert_eq!(fp::FABRICPATH_RULES[0].sid, 467);
    assert_eq!(fp::FABRICPATH_RULES[0].msg, Some("truncated FabricPath header")); // :36
    assert_eq!(fp::FABRICPATH_RULES[1].sid, 0);
    assert_eq!(fp::FABRICPATH_RULES.len(), 2);

    // sids SIX RESIDENT (ZERO new consts, PLAN §1; the h-line cites):
    assert_eq!(cmmod::CodecSid::DECODE_BAD_VLAN as u32, 130);         // :96, h:79
    assert_eq!(cmmod::CodecSid::DECODE_FPATH_HDR_TRUNC as u32, 467);  // :225, h:220
    assert_eq!(cmmod::CodecSid::DECODE_CISCO_META_HDR_TRUNC as u32, 468);   // :226, h:221
    assert_eq!(cmmod::CodecSid::DECODE_CISCO_META_HDR_OPT_LEN as u32, 469); // :227, h:222
    assert_eq!(cmmod::CodecSid::DECODE_CISCO_META_HDR_OPT_TYPE as u32, 470);// :228, h:223
    assert_eq!(cmmod::CodecSid::DECODE_CISCO_META_HDR_SGT as u32, 471);     // :229, h:224

    // HELP faces (faceA :8/:16/:21 pins, verbatim #defines :39/:32/:30):
    assert_eq!(vl::VLAN_API.help, "support for local area network");
    assert_eq!(cm::CISCOMETADATA_API.help, "support for cisco metadata");
    assert_eq!(fp::FABRICPATH_API.help, "support for fabricpath");
}

// ==========================================================================
// 5. VECTORS-face census: EV = 8 lines / SIX distinct sids {130 x3 +
//    467,468,469,470,471 each x1}; EV 116 GID everywhere; all-decimal
//    hygiene BOTH faces; the cite-line census (encode/log/format/pegs
//    CITE-NEVER-CALLED); the GETIDS vlan SET + cisco/fabricpath DECIMAL
//    pins; the graft-v3 DUAL-FACE IGNORE_VLAN pins (pb=0 NO-EV line 6 vs
//    EV+pb=1024 lines 7-8); no tunnel face; THE MPLS NEGATIVE CENSUS
//    grep-0 across BOTH vectors + ALL THREE rs files (the q4 NEVER-land
//    law, cite lines 173-175 NEVER counted — harness survey discipline).
// ==========================================================================
#[test]
fn link4_vector_census() {
    // EV census: EXACTLY-8 lines, SIX distinct sids, GID 116 everywhere:
    let evs: Vec<&str> = VECTORS.lines().filter(|l| l.starts_with("EV ")).collect();
    assert_eq!(evs.len(), 8, "the ground codec_event census: 130x3 + 467 + 468 + 469 + 470 + 471");
    for sid in [130u16, 467, 468, 469, 470, 471] {
        let want_n = if sid == 130 { 3 } else { 1 };
        let n = VECTORS.lines().filter(|l| *l == format!("EV 116 {sid}")).count();
        assert_eq!(n, want_n, "EV {sid} count");
    }
    assert!(evs.iter().all(|l| l.starts_with("EV 116 "))); // GID_DECODE (codec_module.h :38)
    let distinct: std::collections::BTreeSet<&str> = evs.iter().map(|l| l.rsplit(' ').next().unwrap()).collect();
    assert_eq!(distinct.len(), 6, "EV census 8/6-distinct (the harness face)");
    // all-decimal hygiene (harness grep-0 face, BOTH faces):
    assert!(!VECTORS.contains("0x"), "DEC face carries a hex literal");
    assert!(!VECTORS_FACE_A.contains("0x"), "FACE-A carries a hex literal");
    // the cite lines ride verbatim (the three order-sites + the four
    // cited-never-called families + the pegs not-vectorized face):
    assert!(VECTORS.contains("V order-site ext:141->143-before-badvid:145->148 pb0-vs-1024 cite"));
    assert!(VECTORS.contains("F order-site next:84-before-lyr:85 cite"));
    assert!(VECTORS.contains("C order-site ver:116-len:122-opt:130-type:141-sgt:149-lyr:155 cite"));
    assert!(VECTORS.contains("pegs cc:49-:59 CountType-END:53 cited-not-vectorized"));
    assert!(VECTORS.contains("V encode cc:173-:185 + V log cc:154-:171 cited-never-called"));
    assert!(VECTORS.contains("F encode cc:89-:125 + F format cc:127-:137 cited-never-called"));
    assert!(VECTORS.contains("C encode cc:175-:187 + C log cc:165-:173 cited-never-called"));
    // THE IGNORE_VLAN DUAL-FACE PIN (the ext-is-not-decorative face): the
    // pb=0 NO-EV line rides immediately AFTER the qinq line (NO EV 130
    // precedes it), and the EV+pb=1024 pair carries the SAME fixture —
    // positional asserts, both faces of the contrast:
    let lines: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(lines[5], "V vid0-ignore -> 1 lyr=4 next=2048 pb=0", "the ext short-circuit face (:143 BEFORE :148 AND :150)");
    assert_eq!(lines[4], "V qinq -> 1 lyr=4 next=34984", "NO EV line between qinq and vid0-ignore");
    assert_eq!(lines[6], "EV 116 130", "the flag-OFF arm DOES fire (BEFORE its print)");
    assert_eq!(lines[7], "V vid0 -> 1 lyr=4 pb=1024", "the flag-OFF pb face (V5/V6 CONTRAST)");
    // GETIDS DECIMAL faces (SET face tested in test 2; the two singles pin):
    assert!(VECTORS_FACE_A.contains("GETIDS ciscometadata 35081")); // protocol_ids.h :161
    assert!(VECTORS_FACE_A.contains("GETIDS fabricpath 35075"));    // :160
    // the DEC-face DECIMAL pins (the CAST/order faces + the soft-then-
    // continues face):
    assert!(VECTORS.contains("V qinq -> 1 lyr=4 next=34984"));    // the :137 cast
    assert!(VECTORS.contains("F len16 -> 1 next=261 lyr=16"));    // the :84-:85 order clone
    assert!(VECTORS.contains("C sgtffff -> 1 lyr=8 next=2048 flags=4096 pb=131072")); // SOFT then CONTINUE
    assert!(VECTORS.contains("C clean -> 1 lyr=8 next=2048 flags=4096 pb=131072"));   // same tail, NO event
    // no tunnel face ANYWHERE (the §2 trio 0/0 census):
    for face in [VECTORS, VECTORS_FACE_A] {
        assert!(!face.contains("tunnel") && !face.contains("bypass"), "tunnel face crept into vectors");
    }
    // THE MPLS/q4 NEVER-LAND NEGATIVE CENSUS (the deferred-row law; the
    // harness pins MPLS grep-0 in probe.cc/probe_dec.cc/witness_pkthdr.cc
    // — mirrored Rust-side): grep-0 ACROSS the vectors + ALL THREE rs
    // files (case-insensitive token scan in the unit below is the Rust-
    // side twin of that build.sh survey).
    for face in [VECTORS, VECTORS_FACE_A] {
        for tok in ["mpls", "MPLS", "Mpls"] {
            assert!(!face.contains(tok), "a deferred-TU token crept into vectors: {tok}");
        }
    }
    const V_RS: &str = include_str!("../src/codecs/cd_vlan.rs");
    const C_RS: &str = include_str!("../src/codecs/cd_ciscometadata.rs");
    const F_RS: &str = include_str!("../src/codecs/cd_fabricpath.rs");
    for rs in [V_RS, C_RS, F_RS] {
        assert!(!rs.to_lowercase().contains("mpls"), "a deferred-TU token landed in the Rust trio");
    }
    // the double-contrast LOAD face (ONE line per table vs 18m's TWO):
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOAD ")).count(), 3);
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOADS 1")).count(), 3);
}

// ==========================================================================
// 6. UNIT: the vlan gate ladder — the len boundary, the LLC 1518 boundary
//    sweep, the reserved-vid pair, THE graft-v3 eval-order dual face
//    (flags toggle, same bytes: pb 0-vs-1024 + EV absence), the SET
//    face incl the dedup + stop-on-reject stream grammar, and THE encode
//    mirror (cited-never-called; unit-mirrored like 18l/18m).
// ==========================================================================
#[test]
fn up_link4_vlan_ladder() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = vl::VlanCodec::new(vl::DEFAULT_TPIDS.to_string());

    // len boundary: 3 dies WITH EV 130, lyr NEVER set; 4 passes (:120 is
    // strictly <).
    {
        let p = [0x00u8, 0x0A, 0x08, 0x00];
        let mut cd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        assert!(!c.decode(&fw::RawData { data: &p, len: 3 }, &mut cd, &mut sink, 0));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 130)]);
        assert_eq!(cd.lyr_len, 0, "fail path NEVER sets lyr (cc:123 return)");
    }
    // THE dual-face eval-order pin (the vectors' V5/V6, BEHAVIOR twin):
    // vid-0 bytes, flag ON: NO event, TRUE, pb STAYS 0, lyr DID land 4
    // (:139 before :141 — the ext short-circuits AFTER the lyr write).
    {
        let p = [0x00u8, 0x00, 0x08, 0x00];
        let mut cd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        assert!(c.decode(&fw::RawData { data: &p, len: 4 }, &mut cd, &mut sink, vl::DAQ_PKT_FLAG_IGNORE_VLAN));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![], "the :143 return SKIPS the :148 event");
        assert_eq!((cd.lyr_len, cd.proto_bits), (4, 0), "lyr 4 (:139 BEFORE the ext) + pb NEVER set (:150 skipped)");
        assert_eq!(cd.next_prot_id, 2048); // the :137 write STILL landed before :141
    }
    // same bytes, flag OFF: EV + pb 1024 (:147-:148 SOFT — the tail still
    // lands; TRUE not false).
    {
        let p = [0x00u8, 0x00, 0x08, 0x00];
        let mut cd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        assert!(c.decode(&fw::RawData { data: &p, len: 4 }, &mut cd, &mut sink, 0));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 130)]);
        assert_eq!((cd.lyr_len, cd.proto_bits), (4, vl::PROTO_BIT__VLAN)); // 1024
    }
    // vid 4095 pair arm (upper reserved):
    {
        let p = [0x0Fu8, 0xFF, 0x08, 0x00];
        let mut cd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
        assert!(c.decode(&fw::RawData { data: &p, len: 4 }, &mut cd, &mut sink, 0));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 130)]);
        assert_eq!((cd.lyr_len, cd.proto_bits), (4, 1024));
    }
    // LLC boundary sweep (the :98 1518 gate, ground arithmetic): proto
    // 1518 -> LLC 263; 1519 -> CAST 1519 (the <= face).
    {
        for (hi, lo, want) in [(0x05u8, 0xEEu8, 1518u16), (0x05, 0xEF, 1519)] {
            let p = [0x00, 0x0A, hi, lo];
            let mut cd = fw::CodecData::new(Some(&conf), vl::ETHERTYPE_8021Q);
            assert!(c.decode(&fw::RawData { data: &p, len: 4 }, &mut cd, &mut sink, 0));
            assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
            let got = if want <= vl::ETHERNET_MAX_LEN_ENCAP { fw::protocol_id::ETHERNET_LLC } else { want };
            assert_eq!(cd.next_prot_id, got, "LLC gate {want} face");
        }
    }
    // the SET face incl the tpids stream grammar: the default window
    // yields the FOUR-id SET; a dup inside tpids dedups (the set face);
    // a garbage token STOPS the loop (C stream semantics, honest).
    {
        let mut ids = Vec::new();
        c.get_protocol_ids(&mut ids);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, [33024, 34984, 37120, 37376], "the four-id SET (protocol_ids.h :149/:158 + :49)");
        assert_eq!(ids.len(), 4, "no dup at the default window");
    }
    {
        let dup = vl::VlanCodec::new("0x8100 0x8100 0x1234".to_string());
        let mut ids = Vec::new();
        dup.get_protocol_ids(&mut ids);
        assert_eq!(ids.len(), 3, "the SET dedups (0x8100 == ETHERTYPE_8021Q insert, :103 id_set)");
        let stop = vl::VlanCodec::new("0x9100 junk 0x9200".to_string());
        let mut ids = Vec::new();
        stop.get_protocol_ids(&mut ids);
        assert!(!ids.contains(&37376), "the C stream loop STOPS at a rejected token (:111 while(ss>>val))");
    }
    // encode mirror (:173-:185 cited-never-CALLED; unit-shaped): allocate
    // -> memcpy -> NOT_SET x2 -> true; NO header rewrite (the honest copy
    // face, ppp_encap twin).
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0);
        enc.next_ethertype = 0x1234;
        enc.next_proto = 99;
        let inp = [0x00u8, 0x0A, 0x88, 0xA8, 0xDE, 0xAD];
        assert!(c.encode(&inp, 6, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(6) just succeeded");
        assert_eq!(&out[0..6], &inp); // :179 memcpy, NOTHING rewritten
        assert_eq!(enc.next_ethertype, fw::protocol_id::ETHERTYPE_NOT_SET); // :181
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET); // :182
    }
    // the module set() face (:76-:81 — name-match + string store):
    let mut m = vl::VlanModule::new();
    assert!(m.set("extra_tpid_ether_types", "0x9100 0x9200")); // :79-:80
    assert_eq!(m.get_tpids(), "0x9100 0x9200"); // :69-:70
    assert!(!m.set("bogus", "x"), "the :78 assert-name mismatch NEVER writes");
    // the log seam (cited-never-called; unit mirror): the pri/cfi/vid +
    // Len-vs-Next pair on the :162-:170 format.
    {
        let mut lines = Vec::new();
        let mut lsink = |s: String| lines.push(s);
        c.log(&mut lsink, &[0x60, 0x12, 0x08, 0x00]); // pri 3 << 13 | vid 18 (BE 0x6012)
        assert_eq!(lines[0], "Priority:3(0x3) CFI:0 Vlan_ID:18(0x0012)"); // :162-:165
        assert_eq!(lines[1], "  Next:0x0800"); // :170 (2048 > 1518)
    }
}

// ==========================================================================
// 7. UNIT: the fabricpath gate + the :84-before-:85 OBSERVABLE (both
//    writes land; the order is the cite) + the NEXT-FIRST vs lyr pair
//    cross-check + encode (raw arm / zero-size arm / fwd vs reverse swap
//    pair + the allocate-fail TRUE oddity) + the format reverse swap.
// ==========================================================================
#[test]
fn up_link4_fabricpath() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = fp::FabricPathCodec::new();

    // len boundary: 15 dies EV 467; 16 passes with the BOTH-writes face.
    {
        let p = [0u8; 20];
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_FPATH);
        assert!(!c.decode(&fw::RawData { data: &p, len: 15 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 467)]);
        assert_eq!(cd.lyr_len, 0, "fail path NEVER sets lyr (:81 return)");
    }
    {
        let p = [0u8; 20];
        let mut cd = fw::CodecData::new(Some(&conf), fw::protocol_id::ETHERTYPE_FPATH);
        assert!(c.decode(&fw::RawData { data: &p, len: 16 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        // BOTH writes observable; the ORDER is the cite line (:84 before
        // :85 — the print order `next=261 lyr=16` pins the C sequence):
        assert_eq!((cd.next_prot_id, cd.lyr_len), (261, 16), "the :84-then-:85 face");
        assert_eq!(cd.next_prot_id, fw::protocol_id::ETHERNET_802_3); // landed framework import
    }
    // GETIDS single (the landed FPATH import, NEVER re-authored):
    {
        let mut ids = Vec::new();
        c.get_protocol_ids(&mut ids);
        assert_eq!(ids, vec![35075]);
    }
    // encode arms (:89-:125 cited-never-called; unit mirror): RAW arm =
    // ZERO writes; the zero-size arm sets off WITHOUT touching the header
    // (the alignment face); the grown-buffer arm copies type + the fwd/
    // reverse src/dst pair; allocate-fail returns TRUE (the honest
    // ground oddity :106).
    let hdr = {
        let mut h = [0u8; 16];
        h[0..6].copy_from_slice(&[1, 1, 1, 1, 1, 1]);  // fpath_dst
        h[6..12].copy_from_slice(&[2, 2, 2, 2, 2, 2]); // fpath_src
        h[12..14].copy_from_slice(&[0xAA, 0xBB]);       // fpath_type
        h[14..16].copy_from_slice(&[0xCC, 0xDD]);       // fptag_extra (face-only)
        h
    };
    // RAW arm: NO writes anywhere (enc.flags & ENC_FLAG_RAW -> :93 true,
    // the :95 block SKIPPED, :124 true).
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(fw::ENC_FLAG_RAW, fw::ip_protocol::IP, 64, 0);
        assert!(c.encode(&hdr, &mut enc, &mut buf));
        assert_eq!(buf.size(), 0, "the RAW arm touches NOTHING (no allocate, no off)");
    }
    // zero-size NOT-raw arm: buf.off SET for alignment, then done — the
    // header NEVER copied (:97-:100 then :124).
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        buf.off = 7; // bring a non-init off
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        assert!(c.encode(&hdr, &mut enc, &mut buf));
        assert_eq!((buf.off, buf.size()), (0, 0), "the :99 alignment write, NO allocate on the size-0 arm");
    }
    // grown-buffer FORWARD arm: type + src->src, dst->dst (:111-:115).
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        assert!(buf.allocate(4)); // grow PAST zero so the else leg lands
        let mut enc = fw::EncState::new(fw::ENC_FLAG_FWD, fw::ip_protocol::IP, 64, 0);
        assert!(c.encode(&hdr, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(4)+(16) just succeeded");
        // the C overlay sits at buf.data() START (ho = (FPathHdr*)buf.
        // data() :109) — the FPathHdr overlays out[0..16], the earlier
        // 4-byte window is OVERWRITTEN by the header fields (honest C
        // overlay face, cited at cd_fabricpath.rs :109).
        assert_eq!(&out[6..12], &hdr[6..12], ":114 src -> src");
        assert_eq!(&out[0..6], &hdr[0..6], ":115 dst -> dst");
        assert_eq!(&out[12..14], &[0xAA, 0xBB], ":111 type copy");
    }
    // REVERSE arm: the SWAP pair (:119-:120):
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        assert!(buf.allocate(4));
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0); // NOT forward
        assert!(c.encode(&hdr, &mut enc, &mut buf));
        let out = buf.data().unwrap();
        assert_eq!(&out[6..12], &hdr[0..6], ":119 hi->DST lands in ho->SRC");
        assert_eq!(&out[0..6], &hdr[6..12], ":120 hi->SRC lands in ho->DST");
    }
    // the format reverse swap (cited-never-called; unit mirror like the
    // landed cd_eth format): fwd arm touches NOTHING, reverse swaps the
    // 6-byte halves IN PLACE.
    {
        let mut pkt = hdr;
        c.format(false, &mut pkt);
        assert_eq!(&pkt[..6], &[1, 1, 1, 1, 1, 1], "the fwd format arm is a ZERO-write face");
        c.format(true, &mut pkt);
        assert_eq!(&pkt[..6], &[2, 2, 2, 2, 2, 2], ":135 dst <- src");
        assert_eq!(&pkt[6..12], &[1, 1, 1, 1, 1, 1], ":136 src <- tmp (old dst)");
    }
}

// ==========================================================================
// 8. UNIT: the cisco ladder — the len8 boundary, the TWO stats-only
//    SILENT arms (NO EV — the census face), the 469/470 EV arms, THE
//    soft-EV-then-continues sgt face with the FOUR-write tail face
//    (lyr/next-cast/flags/pb + the :155-:160 order), the const ladder
//    values, and the encode + log unit mirrors (cited-never-called).
// ==========================================================================
#[test]
fn up_link4_ciscometadata_ladder() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = cm::CiscoMetaDataCodec::new();

    // THE SILENT-FAIL pair (stats-only arms :116-:126 — ground fires NO
    // codec_event there; the vectors carry NO EV lines for these arms):
    {
        let mut run = |p: [u8; 8], want_ev: Vec<(u32, u32)>, tag: &str| {
            let mut cd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
            let b = c.decode(&fw::RawData { data: &p, len: 8 }, &mut cd, &mut sink);
            assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), want_ev, "{tag} EV face");
            (b, cd)
        };
        // ver0 / lenf0: FALSE with ZERO events (the :118/:124 stats ride
        // cite-only — PEG cite-never-land):
        let (b, cd) = run([0x00, 1, 0x00, 0x01, 0x00, 0x2A, 0x08, 0x00], vec![], "ver0");
        assert!(!b);
        assert_eq!((cd.lyr_len, cd.next_prot_id), (0, cm::ETHERTYPE_CISCO_META), "silent arm touches NOTHING (:119 return)");
        let (b, _) = run([0x01, 0, 0x00, 0x01, 0x00, 0x2A, 0x08, 0x00], vec![], "lenf0");
        assert!(!b);
        // optlen / opttype: FALSE WITH the events (469/470):
        let (b, _) = run([0x01, 1, 0x20, 0x01, 0x00, 0x2A, 0x08, 0x00], vec![(116, 469)], "optlen1");
        assert!(!b);
        let (b, _) = run([0x01, 1, 0x00, 0x02, 0x00, 0x2A, 0x08, 0x00], vec![(116, 470)], "opttype2");
        assert!(!b);
    }
    // THE SOFT-THEN-CONTINUES face: EV 471 rides AND the decode lands the
    // full tail (TRUE + lyr 8 + next CAST 2048 + CODEC_ETHER_NEXT 4096 +
    // PROTO_BIT__CISCO_META_DATA 131072) — the reserved-tag-not-framing
    // face (:148 comment):
    {
        let p = [0x01u8, 1, 0x00, 0x01, 0xFF, 0xFF, 0x08, 0x00];
        let mut cd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        assert!(c.decode(&fw::RawData { data: &p, len: 8 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 471)]);
        assert_eq!((cd.lyr_len, cd.codec_flags), (8, fw::CODEC_ETHER_NEXT));
        assert_eq!(cd.next_prot_id, 2048, "the :157 cast face");
        assert_eq!(cd.proto_bits, cm::PROTO_BIT__CISCO_META_DATA); // 131072
    }
    // the len boundary (7 dies EV 468, 8 passes):
    {
        let p = [0u8; 4];
        let mut cd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        assert!(!c.decode(&fw::RawData { data: &p, len: 7 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 468)]);
    }
    // the const ladder face (ground sed-pinned values):
    assert_eq!((cm::CISCO_META_VALID_HDR_VER, cm::CISCO_META_VALID_HDR_LEN, cm::CISCO_META_VALID_OPT_LEN), (1, 1, 0)); // :93-:95
    assert_eq!(cm::CISCO_META_OPT_LEN_SHIFT, 13);      // :96
    assert_eq!((cm::CISCO_META_OPT_TYPE_SGT, cm::CISCO_META_OPT_TYPE_MASK), (1, 0x1FFF)); // :97-:98
    // the opt-field decode arithmetic faces (0x2001 -> len 1 EV; 0x0002
    // -> type 2 EV; a legal 0x2001-type-1 window: len>0 dies FIRST at
    // :134 — the ORDER ladder, var-before-gate:134/:141):
    {
        let p = [0x01u8, 1, 0x20, 0x02, 0x00, 0x2A, 0x08, 0x00]; // len leg AND type bad: len gate FIRST (:134 before :141)
        let mut cd = fw::CodecData::new(Some(&conf), cm::ETHERTYPE_CISCO_META);
        assert!(!c.decode(&fw::RawData { data: &p, len: 8 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 469)], "the :134-:138 gate lands BEFORE the :141 gate (ONE event)");
    }
    // encode mirror (:175-:187): allocate -> memcpy -> NOT_SET x2 (the
    // vlan encode twin face):
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0);
        enc.next_ethertype = 0x1234;
        enc.next_proto = 99;
        let inp = [0x01u8, 1, 0x00, 0x01, 0x00, 0x2A, 0x08, 0x00];
        assert!(c.encode(&inp, 8, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(8) just succeeded");
        assert_eq!(&out[0..8], &inp); // :181
        assert_eq!(enc.next_ethertype, fw::protocol_id::ETHERTYPE_NOT_SET); // :183
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET); // :184
    }
    // log seam (cited-never-called): the :171 format with the DOUBLE-
    // space separators + the %X uppercase face; sgt_val = ntohs (h:37).
    {
        let mut lines = Vec::new();
        let mut lsink = |s: String| lines.push(s);
        c.log(&mut lsink, &[0x01, 1, 0x00, 0x01, 0x00, 0x2A, 0x86, 0xDD]);
        assert_eq!(lines[0], "Ver:1  SGT:42  EtherNext:0x86DD"); // %hhu / %hu / %X, two-space pairs
    }
}

// ==========================================================================
// 9. THE graft-seam left-open + SET + const-bridge pins (the witness
//    mirror is a PARAM, NEVER an invented provider): the 0x40 flag value
//    == the vectors' ext-arm fixture; PROTO_BIT__VLAN 1024 +
//    PROTO_BIT__CISCO_META_DATA 131072 + CODEC_ETHER_NEXT 4096 pin the
//    vectors' pb-/flags- prints; the three init-prot constants equal the
//    probe's CodecData init ids; the SET == the faceA four-id face.
// ==========================================================================
#[test]
fn up_link4_graft_seam_and_consts() {
    // the graft-v3 DECL-face const (copy daq.h :38, SYNTHETIC graft, row
    // 20 re-cites the real SDK header — NEVER ABI truth):
    assert_eq!(vl::DAQ_PKT_FLAG_IGNORE_VLAN, 0x40); // graft daq.h :38 face
    // the vectors' dual-face prints ride the SAME numbers (the const IS
    // the harness V5 arm's toggle value — the witness-mirror seam):
    assert!(VECTORS.contains("V vid0-ignore -> 1 lyr=4 next=2048 pb=0"));
    assert!(VECTORS.contains("V vid0 -> 1 lyr=4 pb=1024"));
    // the pb/flags consts bridge to the vectors' prints (row-scoped
    // homes w/ h-line cites — NEVER framework re-authors):
    assert_eq!(vl::PROTO_BIT__VLAN, 1024);                          // decode_data.h:97, == pb=1024
    assert_eq!(cm::PROTO_BIT__CISCO_META_DATA, 131072);             // decode_data.h:104, == pb=131072
    assert_eq!(fw::CODEC_ETHER_NEXT, 4096);                         // codec.rs:54 LANDED, == flags=4096
    // the probe's three CodecData init ids (the probe_dec.cc fixture
    // face) == the landed protocol constants:
    assert_eq!(vl::ETHERTYPE_8021Q, 33024);                          // protocol_ids.h :149
    assert_eq!(vl::ETHERTYPE_8021AD, 34984);                         // :158
    assert_eq!(cm::ETHERTYPE_CISCO_META, 35081);                     // :161
    assert_eq!(fw::protocol_id::ETHERTYPE_FPATH, 35075);             // :160 LANDED import
    assert_eq!(fw::protocol_id::ETHERNET_LLC, 263);                  // :134 LANDED import (:135 write)
    assert_eq!(fw::protocol_id::ETHERNET_802_3, 261);                // :132 LANDED import (:84 write)
    // the SET face == the faceA four-id block (same numbers, cross-face):
    let conf_ids: std::collections::BTreeSet<u16> = [vl::ETHERTYPE_8021Q, vl::ETHERTYPE_8021AD, 0x9100, 0x9200].into_iter().collect();
    assert_eq!(conf_ids.into_iter().map(u32::from).sum::<u32>(), 33024 + 34984 + 37120 + 37376, "the tpids pair == 0x9100/0x9200 (the :49 default rides)");
    // the header-size gates (DISK arms): vlan 4 (vlan.h TWO u16s :31-:32),
    // cisco 8 (h:31-:35 fivesome), fabricpath 16 (cc :70 constexpr ==
    // FPathHdr 6+6+2+2):
    assert_eq!(vl::VLAN_TAG_HDR_SIZE, 4);
    assert_eq!(cm::CISCO_META_HDR_SIZE, 8);
    assert_eq!(fp::FABRICPATH_HEADER_LEN, 16);
    assert_eq!(fp::FPATH_TAG_OFF, 14, "the face-only fptag_extra slot (cppcheck-suppress :66)");
}
