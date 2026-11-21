//! Parity test for the row-18m codecs/link PPP DRIFT-PAIR ports — two
//! ground TUs (link/cd_pppoe.cc 243 L md5 65109bbd2bd8837140568f35bdf98eb5
//! / link/cd_ppp_encap.cc 174 L md5 3a254d9eeb93298d8fc548f84ad6cad0; wc
//! 243/174 + the 417 SUM re-measured and asserted EVERY build by
//! tools/link6_harness/build.sh). ZERO-gate row (20th straight honest
//! face): find src/codecs/link -type d -name test = 0 — the link dir has
//! NO test/ AT ALL + add_cpputest census 0 → this suite carries NO
//! up_gate_* set: honest absence, census-cited (PLAN §0).
//!
//! Ground truth #1: `tools/link6_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 20 L md5 e59f7a8a70d172261dcb847dcfdcb36a NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session (per-index assert_eq over want.len()==20). THE R6 EVAL-ORDER
//! RULE REPLAYS: every decode bool lands in a var BEFORE the summary
//! line and every `EV 116 <sid>` lands between the decode call and its
//! printf, NEVER sorted. THE drift-pair EV census: EV 116 fires ONLY on
//! the pppoe side {120, 479} EXACTLY-1-each (build.sh ground census
//! `codec_event` 0 in cd_ppp_encap.cc — the ZERO-codec_event TU face).
//! THE PAIR-LINK face: `PS len6 -> 1 lyr=6 next=34827` (cc:160/:161,
//! order-site cite line :8) == FACE-A `GETIDS ppp_encap 34827` (cc:52) —
//! asserted BOTH sides below (the ground decode-chain family, PLAN §1).
//! The disc-happy ZERO-write face (:3 `PD len6 -> 1 lyr=0 next=34915` —
//! cc:136 bare return, next rides the CodecData init) + the FIXIT-M
//! `proto9=6` face (:19, honest print of the probe's OWN mutated
//! fixture) + the session/order/encode CITE lines ride verbatim.
//!
//! Ground truth #2: `tools/link6_harness/vectors_faceA.txt` — the FACE-A
//! load/walk face (probe.cc over the TWO hidden-BUILDING_SO tables), 20 L
//! md5 d2fc5591bc45c1787fcee7393675a3d8. THE double-NAME headline replays
//! FIRST: `LOAD pppoe_disc` + `LOAD pppoe_sess` = TWO LOAD lines from ONE
//! table (cd_pppoepkt feeds cc:239/:240 — the FIRST double-NAME LOAD face
//! in the port) + `LOADS 2`. The mod-arms census MEASURED 1/1 + 1/1 +
//! 0/0 (:9/:14 real disc/sess pairs cc:200/:201 + cc:222/:223 vs the
//! pppencap EXPLICIT nullptr pair :155/:156 — NO prior row's face
//! carried). GETIDS 34915/34916/34827 DECIMAL (protocol_ids.h :155/:156/
//! :152). The pair ladder names "cd_pppencap"/"cd_pppoepkt" were ALREADY
//! resident (codec_api.rs :122/:123) — this row TURNS them loaded.

use snort3::codecs::cd_ppp_encap as pe;
use snort3::codecs::cd_pppoe as ppoee;
use snort3::codecs::codec_api as capi;
use snort3::framework::codec as fw;
use snort3::parser::parse_conf::SnortConfig;

const VECTORS: &str = include_str!("../tools/link6_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/link6_harness/vectors_faceA.txt");

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 20 lines, ORDERED,
//    ONE session (probe_dec.cc statement order, R6 var-first mirrored;
//    fixtures copied EXACTLY from probe_dec.cc: the z[4096] zeros, the
//    {0x21,0}/2 comp fixtures, the 21-B + 22-B vjucomp fixtures, the
//    {0x00,0x57}/{0x00,0x2b}/{0,0} ladder fixtures).
// ==========================================================================
#[test]
fn link6_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 20, "vectors.txt must hold the full 20-line DEC ladder");

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
    // the probe's ctor faces: ad->ctor(nullptr) / as->ctor(nullptr) /
    // ap->ctor(nullptr) off the TWO tables; the mod pair feeds the
    // double-NAME module face silently.
    let m_disc = ppoee::PPPoEModule::new_disc(); // disc_mod_ctor cc:171 (silent)
    let m_sess = ppoee::PPPoEModule::new_sess(); // sess_mod_ctor cc:174 (silent)
    let _ = (&m_disc, &m_sess);
    let cd = ppoee::PppoeDiscCodec::new(); // cc:180 disc_ctor
    let cs = ppoee::PppoeSessCodec::new(); // cc:183 sess_ctor
    let cp = pe::PppEncap::new();          // :138 ctor

    let z = [0u8; 4096]; // probe's `uint8_t z[4096]={0}`

    // ---- pppoe_disc: the 120 soft gate + the ZERO-write happy face ----
    // vectors:1/:2 — len5 < 6 (:130) -> EV 120 (:132); lyr NEVER set (:133).
    {
        let raw = fw::RawData { data: &z, len: 5 };
        let mut cdd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_DISC);
        let b = cd.decode(&raw, &mut cdd, &mut sink); // bool var FIRST (R6)
        push(format!("PD len5 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:3 — len6 happy cc:136: ZERO lyr/next EVER written; next
    // rides the CodecData INIT prot 34915 (cited face, never invented).
    {
        let raw = fw::RawData { data: &z, len: 6 };
        let mut cdd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_DISC);
        let b = cd.decode(&raw, &mut cdd, &mut sink);
        push(format!("PD len6 -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:4 — the encode CITE line (cited-never-called, NEVER a fake
    // encode print through the transcript).
    push("PD encode cc:92-:105 cited-never-called EncState-IpApi face".to_string());

    // ---- pppoe_sess: the 479 arm + THE PAIR-LINK happy face ----
    // vectors:5/:6 — len5 -> EV 479 (:154-:156); lyr NEVER set.
    {
        let raw = fw::RawData { data: &z, len: 5 };
        let mut cdd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_SESS);
        let b = cs.decode(&raw, &mut cdd, &mut sink);
        push(format!("PS len5 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:7 — len6: lyr=6 BEFORE next=ETHERTYPE_PPP 34827 (cc:160/
    // :161 — the pair-link pin; THE family assert rides test 8).
    {
        let raw = fw::RawData { data: &z, len: 6 };
        let mut cdd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_SESS);
        let b = cs.decode(&raw, &mut cdd, &mut sink);
        push(format!("PS len6 -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:8/:9 — the order-site + session-hdr CITE lines verbatim
    // (the PADT grep-0 NEVER-pull ruling rides the :9 cite line itself).
    push("PS order-site lyr:160-before-next:161 cite".to_string());
    push("PS session-hdr cc:41 session field cited-never-ported (PADT grep-0 ground NEVER-pull face)".to_string());

    // ---- ppp_encap: the switch ladder, ZERO events on EVERY arm ----
    // vectors:10 — len1 -> false :58-:59, NO event ever (the ZERO-
    // codec_event TU face).
    {
        let raw = fw::RawData { data: &z, len: 1 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE len1 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:11 — {0x21,0}: the ODD branch lyr=1 (:66-:67), the
    // compression-collision: 0x21 == PPP_IP NUMERICALLY -> next IPV4
    // (:82 -> :103).
    {
        let p = [0x21u8, 0x00];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE comp21 -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:12 — {0x2d,0}: lyr=1 then 0x2d == PPP_VJ_COMP -> false :83,
    // lyr STAYS (the lyr:73/-:66-before-switch:80 order face), next rides
    // the init 34827.
    {
        let p = [0x2du8, 0x00];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE comp2d -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:13 — {0x00,0x21}: 2-octet face lyr=2 (:71-:73) -> IPV4.
    {
        let p = [0x00u8, 0x21];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE ip -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:14 — {0x00,0x2d}: :83 return false, lyr 2 STAYS.
    {
        let p = [0x00u8, 0x2d];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE vjcomp -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:15 — 21 B: 21 < lyr 2 + IP4_HEADER_LEN 20 (:88-:91) false.
    {
        let p = [0x00u8, 0x2f, 0x45];
        let raw = fw::RawData { data: &p, len: 21 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE vjucomp21 -> {} lyr={}", b as i32, cdd.lyr_len));
    }
    // vectors:16 — 22 B: the FIXIT-M face. The probe MUTATED its OWN
    // fixture through the :97-:98 const_cast and printed p[11] post-
    // decode (probe_dec.cc:87-:89) — the replay mirrors that cited write
    // to the fixture (the vectors pin proto9=6 is the RUNNER-MEASURED
    // ground face); the PORT carries the folded read-only deviation
    // (KNOWN DEVIATIONS row 18m; the cd_no_next.rs:14-:19 precedent).
    {
        let mut p = [0x00u8, 0x2f, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 0, 0];
        p[11] = 6; // the CCMUTATED proto byte face (cc:98 set_proto(TCP)=6, printed honest)
        let raw = fw::RawData { data: &p, len: 22 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!(
            "PE vjucomp22 -> {} lyr={} next={} proto9={}",
            b as i32, cdd.lyr_len, cdd.next_prot_id, p[11]
        ));
    }
    // vectors:17 — {0x00,0x57} -> :107 IPV6 34525.
    {
        let p = [0x00u8, 0x57];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE ipv6 -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:18 — {0x00,0x2b} -> :111 IPX 33079.
    {
        let p = [0x00u8, 0x2b];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE ipx -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:19 — {0,0} -> default :114-:115 true, next UNSET (init
    // 34827 face).
    {
        let p = [0x00u8, 0x00];
        let raw = fw::RawData { data: &p, len: 2 };
        let mut cdd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = cp.decode(&raw, &mut cdd, &mut sink);
        push(format!("PE default -> {} lyr={} next={}", b as i32, cdd.lyr_len, cdd.next_prot_id));
    }
    // vectors:20 — the order-site + encode CITE line (the R6-clone order
    // face + cited-never-called), verbatim.
    push("PE order-site lyr:73-before-switch:80 cite; PE encode cc:120-:132 cited-never-called".to_string());

    let got = out.borrow();
    assert_eq!(got.len(), 20, "replay transcript length must equal the pinned face");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 2. FACE-A replay — vectors_faceA.txt 20 lines (probe.cc in-probe
//    PluginManager::load_plugins witness walking the TWO hidden-
//    BUILDING_SO tables cd_pppoepkt (nm D EXACTLY-1) + cd_pppencap).
//    THE double-NAME LOAD face FIRST: ONE table -> TWO LOAD lines.
// ==========================================================================
#[test]
fn link6_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 20, "vectors_faceA.txt must hold the full 20-line walk");

    let mut got: Vec<String> = Vec::new();

    // witness load face :38-:39 `for (; p && *p; ++p) printf("LOAD %s")`
    // + the probe's explicit per-table counts (:43/:45 `LOADS 2`/`LOADS
    // 1`): ONE walk over cd_pppoepkt prints TWO lines (feeds cc:239/:240
    // — the double-NAME headline); cd_pppencap ONE line (:172).
    for tab in [ppoee::CD_PPPOEPKT, pe::CD_PPPENCAP] {
        for rec in tab.iter() {
            got.push(format!("LOAD {}", rec.name));
        }
        got.push(format!("LOADS {}", tab.len()));
    }

    // probe.cc tabs[3] = { cd_pppoepkt[0], cd_pppoepkt[1], cd_pppencap[0] }:
    let tabs = [
        (ppoee::CD_PPPOEPKT[0], "pppoe_disc"),
        (ppoee::CD_PPPOEPKT[1], "pppoe_sess"),
        (pe::CD_PPPENCAP[0], "ppp_encap"),
    ];
    for (a, tag) in tabs {
        got.push(format!(
            "API {} type={} size={} ver={} name={}",
            tag, a.ptype, a.size, a.api_version, a.name
        ));
        got.push(format!("HELP {} {}", tag, a.help));
        // THE mod-arms MEASURED face (NEVER carried): disc :200/:201 +
        // sess :222/:223 REAL vs the pppencap nullptr pair :155/:156.
        got.push(format!("{} mod_ctor={} mod_dtor={}", tag, a.mod_ctor as u8, a.mod_dtor as u8));
        // ca->ctor(nullptr): ctor/dtor SET x3 cc:207/:208 + :229/:230 + :162/:163.
        got.push(format!("{} ctor={} dtor={}", tag, a.ctor as u8, a.dtor as u8));
        // c->get_protocol_ids(ids) -> GETIDS DECIMAL 34915/34916/34827.
        match tag {
            "pppoe_disc" => {
                let mut ids = Vec::new();
                ppoee::PppoeDiscCodec::new().get_protocol_ids(&mut ids);
                for id in ids { got.push(format!("GETIDS {tag} {id}")); }
            }
            "pppoe_sess" => {
                let mut ids = Vec::new();
                ppoee::PppoeSessCodec::new().get_protocol_ids(&mut ids);
                for id in ids { got.push(format!("GETIDS {tag} {id}")); }
            }
            _ => {
                let mut ids = Vec::new();
                pe::PppEncap::new().get_protocol_ids(&mut ids);
                for id in ids { got.push(format!("GETIDS {tag} {id}")); }
            }
        }
        // ca->dtor(c): the stack-owned Rust fold (18d posture), silent.
    }

    assert_eq!(got.len(), 20);
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "faceA line {}: replay {:?} != measured {:?}", i + 1, g, w);
    }
}

// ==========================================================================
// 3. HIDDEN-TABLE tripwires + THE drift-name refusal faces (PLAN §5 +
//    §87 build.sh mirrors). The C tables: cd_pppoe.cc BUILDING_SO :233,
//    table `cd_pppoepkt[]` :236 feeds :239/:240 DOUBLE; cd_ppp_encap.cc
//    BUILDING_SO :166, table `cd_pppencap[]` :169 feeds :172. nm: the .o
//    defines cd_pppoepkt / cd_pppencap EXACTLY-1, the FILE-base spellings
//    `cd_pppoe$` / `cd_ppp_encap$` EXACTLY-0 (the harness drift refusal)
//    — mirrored Rust-side: the consts ride the TABLE spellings, the
//    files keep the FILE bases, and NO file-base-named table const ever
//    lands.
// ==========================================================================
#[test]
fn link6_hidden_table_tripwire() {
    const P_RS: &str = include_str!("../src/codecs/cd_pppoe.rs");
    const E_RS: &str = include_str!("../src/codecs/cd_ppp_encap.rs");
    // THE drift-table const pins (renaming a const trips THIS assert):
    assert!(
        P_RS.contains("pub const CD_PPPOEPKT: CodecTable = &[&PPPOEPKT_DISC_API, &PPPOEPKT_SESS_API];"),
        "the cd_pppoepkt double-feed drift-table const face drifted (feeds cc:239/:240)"
    );
    assert!(
        E_RS.contains("pub const CD_PPPENCAP: CodecTable = &[&PPPENCAP_API];"),
        "the cd_pppencap drift-table const face drifted (table :169, feed :172)"
    );
    // the hidden-BUILDING_SO cite lines ride BOTH source faces:
    assert!(P_RS.contains("const BaseApi* cd_pppoepkt[] =") || P_RS.contains("`const BaseApi* cd_pppoepkt[]`")); // cc:236 cite
    assert!(E_RS.contains("const BaseApi* cd_pppencap[] =") || E_RS.contains("`const BaseApi* cd_pppencap[]`")); // :169 cite
    // the drift-refusal faces (build.sh nm pins `cd_pppoe$`/`cd_ppp_encap$`
    // EXACTLY-0 mirrored): NO file-base-named TABLE const lands in either
    // file (the FILE-base name rides the landing FILE + cites ONLY):
    assert!(!P_RS.contains("pub const CD_PPPOE: CodecTable"), "the file base must NOT become a table name");
    assert!(!E_RS.contains("pub const CD_PPP_ENCAP: CodecTable"), "the file base must NOT become a table name");
    // the file base names DO ride their landing files (the honesty face):
    assert!(P_RS.contains("cd_pppoe.cc") && P_RS.contains("cd_pppoe.rs"));
    assert!(E_RS.contains("cd_ppp_encap.cc") && E_RS.contains("cd_ppp_encap.rs"));
    // ZERO #[no_mangle] in the pair (the src-wide landed pattern):
    assert!(!P_RS.contains("#[no_mangle]"));
    assert!(!E_RS.contains("#[no_mangle]"));
    // sibling-TEXT refusal (the §87 face: neither TU NAMES the other's
    // table; the ONLY real coupling is the ETHERTYPE_PPP family id):
    assert!(!E_RS.contains("cd_pppoepkt") && !E_RS.contains("PPPOEPKT"),
        "the ppp_encap TU must NOT name the pppoe table — sibling refusal");
    // (cd_pppoe.rs DOES cite its mate's FILE honestly — the family-link
    // cite is a doc cite, never a use-import:)
    assert!(!P_RS.contains("use crate::codecs::cd_ppp_encap"), "family cite rides, NEVER lands as an import");
    assert!(!E_RS.contains("use crate::codecs::cd_pppoe"), "family cite rides, NEVER lands as an import");
    // the NAME pair lives INSIDE cd_pppoe.rs at the MACRO level (both
    // spellings land; the double-NAME headline):
    assert_eq!(ppoee::CD_PPPOEPKT_DISC_NAME, "pppoe_disc"); // cc:115
    assert_eq!(ppoee::CD_PPPOEPKT_SESS_NAME, "pppoe_sess"); // cc:139
    assert_eq!(ppoee::CD_PPPOEPKT.len(), 2, "ONE table, TWO feeds (cc:239/:240) — the double-LOAD pin");
    assert_eq!(pe::CD_PPPENCAP.len(), 1); // :172 single feed
    // feed identity:
    assert!(std::ptr::eq(ppoee::CD_PPPOEPKT[0], &ppoee::PPPOEPKT_DISC_API)); // &pppoepkt_disc_api.base cc:239
    assert!(std::ptr::eq(ppoee::CD_PPPOEPKT[1], &ppoee::PPPOEPKT_SESS_API)); // &pppoepkt_sess_api.base cc:240
    assert!(std::ptr::eq(pe::CD_PPPENCAP[0], &pe::PPPENCAP_API));            // &pppencap_api.base :172

    // the ladder pair RESIDENT (codec_api.rs :122/:123 — the DRIFT
    // spellings; NEVER re-touched; THIS row TURNS them loaded):
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_pppencap"));
    assert!(capi::STATIC_CODEC_EXTERN_NAMES.contains(&"cd_pppoepkt"));
    assert_eq!(
        capi::STATIC_CODEC_EXTERN_NAMES.len(),
        34,
        "the 34-name ladder is row-resident; 18m adds NO new externs"
    );
}

// ==========================================================================
// 4. THE record census: FOUR records 112/1900547/PT_CODEC, ctor/dtor SET
//    x4, g/t nullptr x4 x4, and the mod arms MIRROR MEASURED 1,1/1,1/0,0
//    (disc cc:200/:201 REAL + sess cc:222/:223 REAL vs pppencap nullptr
//    :155/:156) — NO prior row's 1/1/0 face carried. THE RuleMap census
//    (ONE row + terminator x2, msgs byte-exact) + THE sids RESIDENT face
//    {120,479} (codec_module.rs :95/:237, ZERO new consts).
// ==========================================================================
#[test]
fn link6_record_census() {
    for a in [ppoee::PPPOEPKT_DISC_API, ppoee::PPPOEPKT_SESS_API, pe::PPPENCAP_API] {
        assert_eq!(a.ptype, fw::PT_CODEC);          // :192/:214/:147
        assert_eq!(a.size, 112);                    // sizeof(CodecApi), the faceA size pin x3
        assert_eq!(a.api_version, 1900547);         // the faceA ver pin x3
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
    // THE mod-arms MIRROR 1,1 / 1,1 / 0,0 (faceA :9/:14/:19): the REAL
    // disc pair cc:171+cc:177 -> :200/:201; the REAL sess pair cc:174+
    // cc:177 -> :222/:223; the pppencap EXPLICIT nullptr pair :155/:156
    // (the tail's ONLY — contrast 18l's trans_bridge face, NEVER carried).
    // The record fields ARE compile-time consts (the ext_parity_test.rs:
    // 589 / small4_parity_test.rs:594 / misc3_parity_test.rs:486 /
    // erspan_parity_test.rs:378 assertions_on_constants lineage precedent
    // — point-site allow):
    #[allow(clippy::assertions_on_constants)] // pinned record-const face (lineage precedent, point-site)
    {
        assert!(ppoee::PPPOEPKT_DISC_API.mod_ctor, "disc mod_ctor MUST be REAL (disc_mod_ctor cc:171 -> slot :200)");
        assert!(ppoee::PPPOEPKT_DISC_API.mod_dtor, "disc mod_dtor MUST be REAL (mod_dtor cc:177 -> slot :201)");
        assert!(ppoee::PPPOEPKT_SESS_API.mod_ctor, "sess mod_ctor MUST be REAL (sess_mod_ctor cc:174 -> slot :222)");
        assert!(ppoee::PPPOEPKT_SESS_API.mod_dtor, "sess mod_dtor MUST be REAL (mod_dtor cc:177 -> slot :223)");
        assert!(!pe::PPPENCAP_API.mod_ctor, "pppencap mod_ctor MUST be the nullptr arm :155");
        assert!(!pe::PPPENCAP_API.mod_dtor, "pppencap mod_dtor MUST be the nullptr arm :156");
    }

    // the module faces (the 1,1 side): PPPoEModule ONE class TWO instances
    // (cc:62-:73; the THREE-arg shape — name/help + stored rules):
    use snort3::codecs::codec_module as cm;
    let md = ppoee::PPPoEModule::new_disc();
    assert_eq!(md.base.name, "pppoe_disc");
    assert_eq!(md.base.help, ppoee::CD_PPPOEPKT_DISC_HELP);
    assert_eq!(cm::rule_count(md.get_rules()), 1); // cc:52 (ONE row before the :53 terminator)
    let ms = ppoee::PPPoEModule::new_sess();
    assert_eq!(ms.base.name, "pppoe_sess");
    assert_eq!(ms.base.help, ppoee::CD_PPPOEPKT_SESS_HELP);
    assert_eq!(cm::rule_count(ms.get_rules()), 1); // cc:58
    // NO Module type for pppencap (honest absence — the nullptr pair above).

    // RuleMap census + byte-exact msgs (cc:52/:58):
    assert_eq!(ppoee::PPPOE_DISC_RULES[0].sid, 120);
    assert_eq!(ppoee::PPPOE_DISC_RULES[0].msg, Some("bad PPPOE discovery frame detected"));
    assert_eq!(ppoee::PPPOE_DISC_RULES[1].sid, 0);
    assert_eq!(ppoee::PPPOE_SESS_RULES[0].sid, 479);
    assert_eq!(ppoee::PPPOE_SESS_RULES[0].msg, Some("bad PPPOE session frame detected"));
    assert_eq!(ppoee::PPPOE_SESS_RULES[1].sid, 0);
    assert_eq!(ppoee::PPPOE_DISC_RULES.len(), 2);
    assert_eq!(ppoee::PPPOE_SESS_RULES.len(), 2);

    // sids RESIDENT (ZERO new consts, PLAN §4; the h-line cites):
    assert_eq!(cm::CodecSid::DECODE_BAD_PPPOE_DISC as u32, 120); // :95, h:78
    assert_eq!(cm::CodecSid::DECODE_BAD_PPPOE_SESS as u32, 479); // :237, h:232

    // HELP faces (faceA :10/:15/:20 pins, verbatim #defines :116/:140/:30):
    assert_eq!(ppoee::PPPOEPKT_DISC_API.help, "support for point-to-point discovery");
    assert_eq!(ppoee::PPPOEPKT_SESS_API.help, "support for point-to-point session");
    assert_eq!(pe::PPPENCAP_API.help, "support for point-to-point encapsulation");
    // NAME-side faceA: `API/LOAD/HELP` names verbatim:
    assert_eq!(ppoee::PPPOEPKT_DISC_API.name, "pppoe_disc");
    assert_eq!(ppoee::PPPOEPKT_SESS_API.name, "pppoe_sess");
    assert_eq!(pe::PPPENCAP_API.name, "ppp_encap");

    // THE nullptr mod-pair contrast face: 18l's trans_bridge pair stays
    // in ITS file (the pair NEVER crosses): census the two drift rows'
    // own nullptr faces (honest contrast, §5 "do NOT carry a single
    // face across). Inside the allow: compile-time consts again, the
    // same pinned-record-const lineage precedent as the block above.
    #[allow(clippy::assertions_on_constants)] // pinned record-const contrast (lineage precedent, point-site)
    {
        assert!(ppoee::PPPOEPKT_DISC_API.mod_ctor && !pe::PPPENCAP_API.mod_ctor);
    }
}

// ==========================================================================
// 5. VECTORS- face census: EV = {120, 479} EXACTLY-2 pppoe-only lines;
//    ZERO EV on the PE side (the ZERO-codec_event TU face); EV 116 GID
//    everywhere; all-decimal hygiene; the PADT negative census (the §5d3
//    NEVER-pull ruling — the ONLY PADT token in the whole face-set is the
//    vectors:9 ruling cite line ITSELF, ZERO in faceA); the GETIDS +
//    next= DECIMAL pins; the cite-line census.
// ==========================================================================
#[test]
fn link6_vector_census() {
    // EV census: EXACTLY-2 lines, BOTH pppoe sids, ONE each (the pair's
    // EV side; the PE side fires NOTHING — build.sh ground grep census):
    let evs: Vec<&str> = VECTORS.lines().filter(|l| l.starts_with("EV ")).collect();
    assert_eq!(evs.len(), 2, "EV 116 120 + EV 116 479 — the ground codec_event census 2/0");
    assert_eq!(VECTORS.lines().filter(|l| *l == "EV 116 120").count(), 1);
    assert_eq!(VECTORS.lines().filter(|l| *l == "EV 116 479").count(), 1);
    assert!(evs.iter().all(|l| l.starts_with("EV 116 "))); // GID_DECODE (codec_module.h :38)
    // all-decimal hygiene (harness grep-0 face, BOTH faces):
    assert!(!VECTORS.contains("0x"), "DEC face carries a hex literal");
    assert!(!VECTORS_FACE_A.contains("0x"), "FACE-A carries a hex literal");
    // the cite lines ride verbatim (encode x2 CITE-NEVER-CALLED, the two
    // order-site cites, the session-hdr ruling line):
    assert!(VECTORS.contains("PD encode cc:92-:105 cited-never-called EncState-IpApi face"));
    assert!(VECTORS.contains("PS order-site lyr:160-before-next:161 cite"));
    assert!(VECTORS.contains("PE order-site lyr:73-before-switch:80 cite; PE encode cc:120-:132 cited-never-called"));
    // THE PADT NEGATIVE CENSUS (the ruling face pinned): EXACTLY ONE
    // PADT token across BOTH vectors (the vectors:9 ruling cite itself),
    // ZERO in faceA, ZERO as an identifier/arm ANYWHERE in the pair RS:
    assert_eq!(VECTORS.matches("PADT").count(), 1, "the ONLY PADT face is the NEVER-pull ruling line");
    assert_eq!(VECTORS_FACE_A.matches("PADT").count(), 0);
    const P_RS: &str = include_str!("../src/codecs/cd_pppoe.rs");
    const E_RS: &str = include_str!("../src/codecs/cd_ppp_encap.rs");
    for rs in [P_RS, E_RS] {
        assert!(!rs.contains("PADT_") && !rs.contains("PADT =>") && !rs.contains("PPPOE_PADT"),
            "a PADT arm landed — the grep-0 NEVER-pull ruling is dead");
    }
    // the session token is TRUE in the ruling line (honest contrast):
    assert!(VECTORS.contains("PS session-hdr cc:41 session field cited-never-ported (PADT grep-0 ground NEVER-pull face)"));
    // GETIDS DECIMAL faces (protocol_ids.h :155/:156/:152 python-derived):
    assert!(VECTORS_FACE_A.contains("GETIDS pppoe_disc 34915"));
    assert!(VECTORS_FACE_A.contains("GETIDS pppoe_sess 34916"));
    assert!(VECTORS_FACE_A.contains("GETIDS ppp_encap 34827"));
    // the DEC-face DECIMAL pins incl the family id BOTH sides:
    assert!(VECTORS.contains("PD len6 -> 1 lyr=0 next=34915")); // the ZERO-write init face
    assert!(VECTORS.contains("PS len6 -> 1 lyr=6 next=34827"));  // THE PAIR-LINK
    // no tunnel face ANYWHERE (the §2 carried-hook contrast, pair-side 0/0):
    for face in [VECTORS, VECTORS_FACE_A] {
        assert!(!face.contains("tunnel") && !face.contains("bypass"), "tunnel face crept into vectors");
    }
    // the double-NAME LOAD face pinned in the vectors themselves:
    assert!(VECTORS_FACE_A.contains("LOAD pppoe_disc") && VECTORS_FACE_A.contains("LOAD pppoe_sess"));
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOAD ")).count(), 3); // 2+1
}

// ==========================================================================
// 6. UNIT: the pppoe gate ladder boundaries + the disc-happy ZERO-write
//    behavior face + the pppoe encode mirror (cited-never-called by the
//    vectors — unit-mirrored like 18l's TB encode).
// ==========================================================================
#[test]
fn up_link6_pppoe_gates() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));

    // disc boundary: len EXACTLY 6 = PPPOE_HEADER_LEN PASSES (:130 is
    // strictly <); len 5 dies with 120 (:132).
    {
        let p = [0u8; 8];
        let mut cd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_DISC);
        assert!(ppoee::PppoeDiscCodec::new().decode(&fw::RawData { data: &p, len: 6 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        // THE ZERO-WRITE face: cc:136 touches NOTHING — lyr stays 0, next
        // stays the init (the vectors' next=34915 face):
        assert_eq!((cd.lyr_len, cd.next_prot_id), (0, ppoee::ETHERTYPE_PPPOE_DISC));
    }
    {
        let p = [0u8; 8];
        let mut cd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_DISC);
        assert!(!ppoee::PppoeDiscCodec::new().decode(&fw::RawData { data: &p, len: 5 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 120)]);
        assert_eq!(cd.lyr_len, 0, "fail path NEVER sets lyr (cc:133 return)");
    }
    // sess boundary + THE PAIR-LINK writes (order VERBATIM cc:160 before
    // cc:161 — the observable lands BOTH, the order-site is the cite):
    {
        let p = [0u8; 8];
        let mut cd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_SESS);
        assert!(ppoee::PppoeSessCodec::new().decode(&fw::RawData { data: &p, len: 6 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        assert_eq!((cd.lyr_len, cd.next_prot_id), (6, 34827));
        assert_eq!(cd.next_prot_id, pe::ETHERTYPE_PPP); // the family pin (see test 8)
    }
    {
        let p = [0u8; 8];
        let mut cd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_SESS);
        assert!(!ppoee::PppoeSessCodec::new().decode(&fw::RawData { data: &p, len: 5 }, &mut cd, &mut sink));
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![(116, 479)]);
    }
    // gate boundary sweep (NEVER-pull: NO PADT arm exists between :128
    // and :163 — EVERY len>=6 decodes true on both codecs, whatever the
    // code bytes; ground has ZERO code/version checks):
    for len in [6u32, 7, 64, 4096] {
        let p = [0xFFu8; 64]; // garbage code/version bytes — the ground NEVER reads them
        let mut cd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_SESS);
        assert!(ppoee::PppoeSessCodec::new().decode(&fw::RawData { data: &p, len }, &mut cd, &mut sink), "len {len}");
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        assert_eq!((cd.lyr_len, cd.next_prot_id), (6, 34827), "identical writes across len faces");
    }

    // encode face cc:92-:105 (cited-never-CALLED by the vectors; unit-
    // mirrored like the 18l TB encode): allocate -> memcpy -> the htons
    // length rewrite (buf.size()-raw_len == 0 the honest C face) -> the
    // NOT_SET pair.
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0);
        enc.next_ethertype = 0x1234;
        enc.next_proto = 99; // the NOT_SET-reset face needs a non-init value
        let inp = [0x11u8, 0x22, 0x00, 0x0a, 0xAA, 0xBB, 0xCC, 0xDD]; // a PPPoEHdr-shaped 8 B
        assert!(ppoee::PPPoECodecBase::encode(&inp, 8, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(8) just succeeded");
        assert_eq!(&out[0..4], &inp[0..4]);      // cc:98 memcpy head window
        assert_eq!(&out[4..6], &[0x00, 0x00]);   // cc:100 the length slot OVERWRITES the copied AA BB: htons(size-raw_len)=htons(0) — the honest zero face
        assert_eq!(&out[6..8], &inp[6..8]);      // payload beyond the slot rides the memcpy
        assert_eq!(enc.next_ethertype, fw::protocol_id::ETHERTYPE_NOT_SET); // cc:102
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET);         // cc:103
    }
}

// ==========================================================================
// 7. UNIT: the ppp_encap ladder arms + the FIXIT-M folded-deviation
//    BEHAVIOR face (the port NEVER mutates the window — the vectors'
//    proto9=6 rides the probe's own fixture) + the 21-vs-22 boundary +
//    the ppp_encap encode mirror.
// ==========================================================================
#[test]
fn up_link6_ppp_encap_ladder() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));
    let c = pe::PppEncap::new();

    // ZERO-event census across the WHOLE ladder (the :124 face):
    let mut run = |p: &[u8], len: u32, want: (bool, u16, u16), tag: &str| {
        let mut cd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        let b = c.decode(&fw::RawData { data: p, len }, &mut cd, &mut sink);
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![], "{tag}: ZERO codec_event EVER");
        assert_eq!((b, cd.lyr_len, cd.next_prot_id), want, "{tag}");
    };
    run(&[0], 1, (false, 0, 34827), "len1");                      // :58-:59
    run(&[0x21, 0], 2, (true, 1, 2048), "comp21");                // collision face :66-:67 + :82 -> :103
    run(&[0x2d, 0], 2, (false, 1, 34827), "comp2d");              // :83 false, lyr 1 STAYS
    run(&[0x00, 0x21], 2, (true, 2, 2048), "ip");                 // :71-:73 + :103
    run(&[0x00, 0x2d], 2, (false, 2, 34827), "vjcomp");           // :83, lyr 2 STAYS
    run(&[0x00, 0x57], 2, (true, 2, 34525), "ipv6");              // :107
    run(&[0x00, 0x2b], 2, (true, 2, 33079), "ipx");               // :111
    run(&[0x00, 0x00], 2, (true, 2, 34827), "default");           // :114-:115 init stays
    run(&[0x01, 0x00], 2, (true, 1, 34827), "odd 0x01 -> default"); // the 1-B odd face hits default (1 != 0x21 etc.)

    // the 21-vs-22 IP4_HEADER_LEN==20 boundary (:88-:91, ipv4.h :38):
    {
        let p21 = [0x00u8, 0x2f, 0x45]; // 21 declared
        let mut cd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        assert!(!c.decode(&fw::RawData { data: &p21, len: 21 }, &mut cd, &mut sink)); // :91
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        assert_eq!(cd.lyr_len, 2, "vjucomp lyr written BEFORE the len gate (:73) STAYS");
    }
    // THE FIXIT-M folded face: a 22-B fixture; the port reads the :97
    // overlay window and NEVER mutates it (KNOWN DEVIATIONS): byte 11
    // STAYS whatever the caller brought (the vectors' proto9=6 is the
    // probe's own mutated print, mirrored by cite in test 1):
    {
        let p22 = [0x00u8, 0x2f, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 0, 0];
        assert_eq!(p22[11], 0); // the UN-mutated bring value
        let mut cd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        assert!(c.decode(&fw::RawData { data: &p22, len: 22 }, &mut cd, &mut sink)); // :100 fall-through -> :103
        assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
        assert_eq!((cd.lyr_len, cd.next_prot_id), (2, 2048));
        assert_eq!(p22[11], 0, "THE FOLDED FACE: the Rust port NEVER writes the const window (the FIXIT-M ground admits :95-:96)");
    }
    // the odd-branch collision sweep (the compression face rides GROUND):
    for b in [0x21u8, 0x23, 0x29, 0x57, 0x2b, 0x2f, 0x2d] {
        let p = [b, 0x01];
        let mut cd = fw::CodecData::new(Some(&conf), pe::ETHERTYPE_PPP);
        c.decode(&fw::RawData { data: &p, len: 2 }, &mut cd, &mut sink);
        // every odd octet reads lyr=1 (:66) — the FULL protocol match only
        // when the OCTET EQUALS the 16-bit constant (the collision rule):
        assert_eq!(cd.lyr_len, 1, "odd octet {b:#04x} always lyr 1");
    }

    // encode face :120-:131 (cited-never-CALLED; unit mirror): allocate ->
    // memcpy -> NOT_SET x2 -> true; NO length rewrite (the pppoe contrast).
    {
        let mut store = [0u8; 64];
        let mut buf = fw::Buffer::new(&mut store, 64);
        let mut enc = fw::EncState::new(0, fw::ip_protocol::IP, 64, 0);
        enc.next_ethertype = 0x1234;
        enc.next_proto = 99;
        let inp = [0x00u8, 0x21, 0x45, 0x00, 0xDE, 0xAD];
        assert!(c.encode(&inp, 6, &mut enc, &mut buf));
        let out = buf.data().expect("allocate(6) just succeeded");
        assert_eq!(&out[0..6], &inp); // :126 memcpy, NOTHING rewritten afterwards (the :100 contrast)
        assert_eq!(enc.next_ethertype, fw::protocol_id::ETHERTYPE_NOT_SET); // :128
        assert_eq!(enc.next_proto, fw::ip_protocol::PROTO_NOT_SET);         // :129
    }
}

// ==========================================================================
// 8. THE GROUND FAMILY-LINK cross-file asserts (PLAN §1/:26): pppoe sess
//    decode next (cc:161) == ETHERTYPE_PPP == ppp_encap GETIDS (cc:52) ==
//    the vectors' 34827 BOTH sides — the decode-chain family MIRROR; the
//    file-local twin consts pin EQUAL cross-file; the protocol_ids.h
//    ground values pin DECIMAL.
// ==========================================================================
#[test]
fn up_link6_family_link() {
    let conf = SnortConfig::default();
    let evs = std::cell::RefCell::new(Vec::new());
    let mut sink = |g: u32, s: u32| evs.borrow_mut().push((g, s));

    // decode-side: sess happy -> next 34827 ...
    let mut cd = fw::CodecData::new(Some(&conf), ppoee::ETHERTYPE_PPPOE_SESS);
    let p = [0u8; 8];
    assert!(ppoee::PppoeSessCodec::new().decode(&fw::RawData { data: &p, len: 6 }, &mut cd, &mut sink));
    assert_eq!(*std::mem::take(&mut *evs.borrow_mut()), vec![]);
    // ... == the mate's get_protocol_ids id (cc:52) == BOTH twin consts:
    let mut ids = Vec::new();
    pe::PppEncap::new().get_protocol_ids(&mut ids);
    assert_eq!(ids, vec![pe::ETHERTYPE_PPP]);
    assert_eq!(cd.next_prot_id, ids[0], "THE family link: pppoe sess next (cc:161) == ppp_encap GETIDS (cc:52)");
    assert_eq!(ppoee::ETHERTYPE_PPP, pe::ETHERTYPE_PPP, "the file-local twins pin EQUAL (the dup-not-import family)");
    assert_eq!(cd.next_prot_id, 34827); // protocol_ids.h :152 0x880B DECIMAL
    // the vectors' BOTH-side text pins:
    let dec_has_next = VECTORS.contains("PS len6 -> 1 lyr=6 next=34827");
    let fa_has_getids = VECTORS_FACE_A.contains("GETIDS ppp_encap 34827");
    assert!(dec_has_next && fa_has_getids, "the family id rides BOTH vector faces");

    // the pppoe GETIDS pair (protocol_ids.h :155/:156):
    let mut d = Vec::new();
    ppoee::PppoeDiscCodec::new().get_protocol_ids(&mut d);
    assert_eq!(d, vec![34915]); // 0x8863
    let mut s = Vec::new();
    ppoee::PppoeSessCodec::new().get_protocol_ids(&mut s);
    assert_eq!(s, vec![34916]); // 0x8864
    // the decode INIT ids equal the GETIDS ids (the CodecData init face
    // the vectors' PD len6 print rides):
    assert_eq!(ppoee::ETHERTYPE_PPPOE_DISC, 34915);
    assert_eq!(ppoee::ETHERTYPE_PPPOE_SESS, 34916);
}
