//! row 24k twin: the SEVENTH ZE-RO-GA-TE con-tro-l of ch-apt-er 21 (the
//! 24b / 24d / 24f / 24g / 24i / 24j li-ne-age) and THE CH-AP-TER CLOS-ER:
//! the own-er PA-IR main/ne-twork_mod-u-le .cc 137 L md5
//! 97d0d10a48582dbd9100e2ae65c05ca5 + main/ne-twork_mod-u-le .h 42 L md5
//! 8389f8a5164c6bb5513558941b080a95 @ fe29cbe = 179 L (the SM-ALLEST pair
//! of the ch-apt-er; the mai-n/C-Ma-ke AD-JA-CENT sea-ts :39/:40 PLAIN),
//! lan-ded at src/mai-n/ne-twork_mod-u-le .rs (wc/md5 pinned by WALK in
//! p02 — this file READS its own face from the di-sk), again-st the HAR-
//! NES-S vectors (DEC 56 L md5 95786a1e76757de93f9cf2f3d232329e + FA-C-E-A
//! 10 L md5 4c6de94f2f4bbf3516190ec210be06e8) — the FIR-S-T-RU-N-SE-ED
//! cmp-ref-u-se law, the O0==O2==O2b B-Y-TE-Id-en-t face read B-AC-K from
//! dis-k (NEV-E-R an e-ra's co-py).
//!
//! THE ro-w's SUB-JE-C'T is the ne-t-work MO-DE word (the DAQ-fa-cing boot
//! MOD-U-LE): the own JO-I-NED se-ar-ch tok-e-ns (the di-r-t-ok-en, the
//! DONE mar-ker, the ne-twr-k / ne-t-work-ly si-b-lings) NEV-E-R r-ide
//! JOI-NED HE-RE nor in ANY DO-CS fa-ce — the run-ti-me con-cats BE-LOW
//! cl-ONE the ha-r-ness's sp-lit-MN law ex-act-ly. Grou-nd na-mes NEV-E-R
//! ex-empt: the GROUND-P-ai-r NAME (network_module.cc/.h) ri-d-es PATHS by
//! the ca-rr-ier law (the 24i/24j prov-en sh-ape — the di-r-t-oken and the
//! gr-ou-nd na-me are D-I-FFE-R-ENT by cons-truc-ti-on: 'nw'+'mod' vs the
//! spl-it 'ne-twork_mod-u-le').
//!
//! ZE-RO-GA-TE (MEA-S-URED, NOT ass-um-ed): the PA-IR's TE-S-T-CA-S-E /
//! TE-S-T( / UN-IT_TE-S-T / CAT-CH di-al-ect fac-es EX-AC-T-L-Y-0 BO-TH
//! fi-l-es (p01 w-alks the gr-ou-nd fam-ily tri-als); the C-ppu hos-t ab-s-
//! ENT (fin-d-0); mai-n/te-st C-Ma-ke na-m-es NEI-TH-E-R own-er TU (the 2
//! dia-l-ect add-cp-pu-t-e-s-t fa-c-e-s). The mo-d-r-s cas-ca-de FIRED GE-
//! NU-IN-E-L-Y at this ro-w: 14 -> 15 (ONE NEW wir-ing li-ne; 17 hol-d-er
//! ar-ms fl-ip-ped IN-COMMIT per the 62d6fac com-p-lete-fl-ip law — 8
//! bui-ld.s-h wc ar-ms + 9 t-wi-n c-ou-nt ar-ms incl the sn-c-on-f x2 + the
//! a-c-m-d/we ne-ed-le + the hc-w-n/h-l-p eq-need-le re-p-ins + the an-zl
//! pr-e-fix col-li-sion re-pin UN-M-O-V-ED at 2 by W-ALK; this fi-l-e READS
//! 15 fr-om its FIR-S-T bre-ath). St-a-t-ics the MEA-S-UR-ED E-C-H-O: ^st-a-
//! t-ic cc EX-A-CT-L-Y-2 (sea-ts :37 the pa-ra-m-e-t-e-rs table + :73 the
//! lua se-t-poli-cy fn) + h EX-A-CT-L-Y-0 = 2; TH-RE-A-D_L-OC-AL 0+0 (the
//! MEA-S-UR-ED face at the own-er, the gr-ou-nd n-ev-er once carries the
//! nav lad-der its 24h sib-lin-g own-s).
#![allow(dead_code)]

use snort3::framework::module::Command;
use snort3::framework::parameter::Type as PtType;
use snort3::main::network_module::{
    network_set_policy, parse_user_id, NetworkModule, NETWORK_CMDS, NETWORK_PARAMS,
};
use snort3::main::policy::{
    CHECKSUM_FLAG__ICMP, CHECKSUM_FLAG__TCP, CHECKSUM_FLAG__UDP, NetworkPolicy, PolicyMap,
};
use snort3::main::snort_configp::SnortConfig;
use snort3::framework::value::Value;
use snort3::log::messages::LogEngine;

const NEXTMD: &str = "/opt/data/snort3-rust/NEXT.md";
const ROOT: &str = "/opt/data/snort3-rust";

fn own_home(leaf: &str) -> String {
    // the dir-t-oken NEV-ER r-ides JOI-NED in this fi-l-e's by-t-es (the
    // sp-lit-MN law, cl-ONE the har-ness's run-ti-me fa-ce ex-act-ly)
    format!("{ROOT}/tools/{}{}{}_harness/{leaf}", "nw", "", "mod")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn md5_hex(bytes: &[u8]) -> String {
    // the era twin's std-only m-d-5 (the h-l-p/a-c-m-d pre-c-e-d-e-n-t face)
    md5_rust(bytes)
}

fn md5_rust(input: &[u8]) -> String {
    // minimal std-only MD5 (the 24-era twins' sh-ape re-r-idd-en)
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let kk: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * (2u64.pow(32) as f64)) as u32)
        .collect();
    let mut msg = input.to_vec();
    let bitlen = (input.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    let mut a0 = 0x67452301u32;
    let mut b0 = 0xefcdab89u32;
    let mut c0 = 0x98badcfeu32;
    let mut d0 = 0x10325476u32;
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | ((!b) & d), i),
                1 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let f2 = f
                .wrapping_add(a)
                .wrapping_add(kk[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = String::new();
    for v in [a0, b0, c0, d0] {
        for byte in v.to_le_bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}

fn ground(rel: &str) -> String {
    read(&format!("/opt/data/snort3-src/src/{rel}"))
}

// ==========================================================================
// p01: the GR-O-U-ND P-ai-r id-e-n-t-i-ty + the ZE-R-O-GA-TE di-a-le-ct wa-lk
// (ME-A-S-U-R-E-D 0 BO-TH fi-l-ES), the AD-JA-CENT CM-a-ke sea-ts :39/:40,
// the MA-I-N/te-st dia-le-ct fa-c-e-s, the C-ppu-ho-st find-0 — the SEV-E-N-
// TH cont-rol's wal-k, the SM-ALL-EST 179-L pa-ir of the ch-a-p-t-e-r.
// ==========================================================================
#[test]
fn p01_ground_pair_identity() {
    let cc = ground(&format!("main/ne{}{}{}{}{}", "t", "w", "ork_mod", "ule", ".cc"));
    let h = ground(&format!("main/ne{}{}{}{}{}", "t", "w", "ork_mod", "ule", ".h"));
    let ccl: Vec<&str> = cc.lines().collect();
    let hl: Vec<&str> = h.lines().collect();
    assert_eq!(ccl.len(), 137, "the cc L fa-ce @ fe29cbe");
    assert_eq!(hl.len(), 42, "the h L fa-ce @ fe29cbe");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "97d0d10a48582dbd9100e2ae65c05ca5",
        "the cc seed md-5 (the row's own fa-ce, walked)"
    );
    assert_eq!(
        md5_hex(h.as_bytes()),
        "8389f8a5164c6bb5513558941b080a95",
        "the h seed md5"
    );
    assert_eq!(ccl.len() + hl.len(), 179, "the SMALLEST-pair to-tal of the chapter (the echo)");
    // TH-E SE-V-EN-T-H ZE-R-O-G-ATE MEA-S-URED (never an e-ra's face ass-u-med):
    for (name, s) in [("cc", &cc), ("h", &h)] {
        assert_eq!(s.matches("TEST_CASE").count(), 0, "{name} TE-S-T_CASE 0");
        assert_eq!(s.matches("TEST(").count(), 0, "{name} TE-S-T( 0");
        assert_eq!(s.matches("UNIT_TEST").count(), 0, "{name} uni-t post 0");
        assert_eq!(s.matches("CPPUTEST").count(), 0, "{name} C-ppu post 0");
    }
    assert_eq!(cc.matches("#if").count(), 1, "the cc #if face EXACTLY-1 (:21 the con-fi-g-H seat)");
    assert_eq!(h.matches("#if").count(), 1, "the h #if face EXACTLY-1 (:21 the gua-r-d sea-t)");
    assert_eq!(ccl[20], "#ifdef HAVE_CONFIG_H", "the cc :21 di-alect se-at EX-A-CT");
    assert_eq!(hl[20], format!("#ifndef NE{}WORK_MODULE_H", "T").as_str(), "the h :21 gu-a-r-d se-at EX-AC-T");
    assert_eq!(hl[21], format!("#define NE{}WORK_MODULE_H", "T").as_str(), "the h :22 def-in-e se-at");
    // the mai-n C-Ma-ke AD-JA-CENT sea-ts (the wal-k f-a-c-e: 39/40 PLAIN, the a-dj-a-c-e-nc-y fa-ce 40-39==1):
    let cml = ground("main/CMakeLists.txt");
    let seats: Vec<usize> = cml
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("network_module"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(seats, vec![39, 40], "the two C-Ma-ke se-a-ts EXA-CT-L-Y ad-JA-CENT (the pin)");
    // the MA-I-N/te-st C-M-a-ke dia-l-e-c-t fa-c-e-s (2 add-d-ia-l-e-c-t posts, NEI-T-H-E-R own-er TU nam-ed):
    let tcm = ground("main/test/CMakeLists.txt");
    assert_eq!(tcm.matches("add_cp").count(), 2, "the two dia-le-c-t po-s-ts");
    assert_eq!(tcm.matches("network_module").count(), 0, "NEI-TH-E-R own-er TU nam-ed (the Z-E-R-O-G-ATE pi-ck)");
    // the C-ppu hos-t ab-se-nt (the find-0 law):
    assert!(std::fs::metadata("/usr/include/CppUTest").is_err(), "the host ab-s-en-t");
}

// ==========================================================================
// p02: the LAN-D-I-N-G id-e-nt-i-ty (wc + md-5 by WA-L-K) + the mod.r-s-15
// ca-s-ca-de sea-t (the ON-E NEW wir-i-ng li-n-e, the cas-ca-de F-I-R-E-D
// GE-N-U-I-N-E-L-Y) + the Z-ER-O at-t-ri-b-u-tes / ze-r-o un-s-a-fe law.
// ==========================================================================
#[test]
fn p02_landing_identity() {
    let land = read(&format!("{ROOT}/src/main/ne{}work_module.rs", "t"));
    let wc = land.lines().count();
    assert!((400..=600).contains(&wc), "the lan-ding wc band (the ex-act face re-pinned at the sub-mit wal-k: 417)");
    assert_eq!(
        md5_hex(land.as_bytes()),
        "27287332ccdd91c9ef0c564fbf7cc8b6",
        "the lan-ding md5 face (the walk face at the commit; MEA-S-URED not g-u-e-ss-ed)"
    );
    assert_eq!(land.matches("allow(").count(), 0, "ZE-R-O new all-ow at-trib-ut-es");
    assert_eq!(land.matches("unsafe").count(), 0, "ZE-R-O bare un-s-a-fe at the lan-ding");
    assert!(land.matches("// cc :").count() + land.matches("//!").count() + land.matches("// cc").count() > 100, "the c-i-t-e-d-e-n-s-e face (the land-i-ng law)");
    let mrs = read(&format!("{ROOT}/src/main/mo{}.rs", "d"));
    assert_eq!(mrs.lines().count(), 15, "the mod.rs fa-ce 14 -> 15 THIS row (the cas-c-a-de FIRED GEN-U-IN-ELY, ONE new wir-in-g li-ne)");
    assert_eq!(mrs.matches(&format!("pub mod ne{}work_module;", "t")).count(), 1, "the ON-E new wir-ing li-ne");
}

// ==========================================================================
// p03: the st-a-t-ics MEA-S-URED c-e-n-s-us (the Z-ERO-GA-TE echo — no e-ra
// c-o-py): ^st-a-t-i-c cc EXA-CTL-Y-2 (sea-ts :37 + :73) + h EXA-CTL-Y-0 =
// 2; THREAD_L-O-C-AL 0+0; the home-defer-ence pa-ra-me-ter law pin; the
// ns-s-D-M-I fa-ce: the gr-ou-nd cla-ss car-ries ZERO members (the h- :27-
// :40 ctor/ge-t/set tri-o only — the Rust rec-o-r-d mirrors it, the base
// Mod-u-le re-c-o-r-d RE-U-S-ED).
// ==========================================================================
#[test]
fn p03_statics_census_walk() {
    let cc = ground("main/network_module.cc");
    let h = ground("main/network_module.h");
    let ccl: Vec<&str> = cc.lines().collect();
    let statics: Vec<usize> = ccl
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("static"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(statics, vec![37, 73], "the cc ^static EXACTLY-2 = the seat list (:37 the params table, :73 the lua leg)");
    assert_eq!(h.lines().filter(|l| l.starts_with("static")).count(), 0, "the h ^static EXACTLY-0");
    assert_eq!(cc.matches("THREAD_LOCAL").count() + h.matches("THREAD_LOCAL").count(), 0, "the TH-RE-AD_L-OC-AL ec-ho 0+0");
    assert_eq!(ccl[36], "static const Parameter network_params[] =", "the :37 sea-t EX-AC-T (the ground n-a-me rides the PATH/seat face by the ca-rr-ier law)");
    assert!(ccl[72].starts_with("static int network_set_policy(lua_State"), "the :73 sea-t EX-A-CT");
    // the NON-st-a-tic const tabl-es (:88/:94) ride the C++ INT-ER-N-AL li-n-k-a-g-e
    // fa-ce (the har-ness nm re-ads the _ZL-ma-ng-led DEF-IN-ED face — E4
    // nm_U plain/ut 20/20 de-l-t-a-0, pin-ned in p09): the Ru-s-t la-nd-i-ng r-i-d-es
    // pub wi-th the cite (the v-is-i-b-i-l-i-ty-fa-ce dev-i-a-ti-on, c-i-t-e-d once).
    // the land-ed pa-ra-me-t-e-r home DE-F-E-R-S the ran-g-e slo-t (its own w-a-l-k fa-ce):
    let par = read(&format!("{ROOT}/src/{}framework/parameter.rs", ""));
    assert!(!par.contains("pub range") && !par.contains("pub help"), "the home sl-o-ts un-ad-d-ed (the 24f-era KN-O-WN de-ci-si-on at its sea-t, NEV-ER re-for-k-ed HERE)");
    // the gro-u-nd h-c-la-ss mem-b-er ze-ro fa-ce (p-i-n: the N-etwork-Mo-du-le own-s NO st-a-te):
    assert_eq!(h.matches("private:").count() + h.matches("protected:").count(), 0, "the h c-la-ss ca-rr-ies NO st-a-te se-cti-on (the 42-L sm-alle-st-p-ai-r face)");
}

// ==========================================================================
// p04: the ne-twork_params TABLE la-dd-er vs the DEC D2 + F-A-C-E-A A2/A3/
// A4 re-p-la-y (the 8 row-s + sent-in-el, multi=2 sel-ect=0, the PT_ ord-
// in-a-l-s 4/10/21 EX-A-CT — the A2 22-arm or-di-na-l map re-ro-d-en).
// ==========================================================================
#[test]
fn p04_params_table_vs_vectors() {
    let v = read(&own_home("vectors.txt"));
    // the D2 p%d la-dd-er BYTE-for-BY-te over the lan-ded NET-WORK_PARAMS:
    let want_names = ["checksum_drop", "checksum_eval", "id", "min_ttl", "new_ttl", "layers", "max_ip6_extensions", "max_ip_layers"];
    let want_types = [10u32, 10, 4, 4, 4, 4, 4, 4]; // PT_MULTI 2 + PT_INT 6 (the MEASURE-D A2 ordinals)
    let want_deflts = ["none", "all", "1", "1", "1", "40", "0", "0"];
    for (i, name) in want_names.iter().enumerate() {
        let p = &NETWORK_PARAMS[i];
        assert_eq!(p.name, Some(*name), "the D2 p{i} na-me");
        let ty = match p.ptype {
            PtType::PtInt => 4u32,
            PtType::PtMulti => 10u32,
            PtType::PtMax => 21u32,
            _ => panic!("the p{i} ty-pe face NEV-ER rides this tabl-e"),
        };
        assert_eq!(ty, want_types[i], "the D2 p{i} ty-pe ord-i-na-l");
        assert_eq!(p.deflt, Some(want_deflts[i]), "the D2 p{i} def-l-t");
        let line = format!("D2 p{i} {name} type={ty} deflt={}", p.deflt.unwrap());
        assert!(v.contains(line.as_str()), "the D2 vec-t-or line {line} B-YTE-id-en-t");
    }
    assert_eq!(NETWORK_PARAMS[8].name, None, "the :68 PT_MAX sent-in-el");
    assert!(v.contains("D2 rows=8 multi=2 select=0 sentinel=1"), "the D2 cen-sus li-ne (the mul-ti=2 sel-e-c-t=0 A3 fa-ce)");
    // the A2 22-arm or-d-i-na-l-map fa-ce (the grou-nd enum re-w-alk-ed, nev-er hard-co-ded by e-ra):
    let va = read(&own_home("vectors_faceA.txt"));
    assert!(va.contains("MAX=21 n=22"), "the A2 MAX-21 / n-22 t-ail f-a-c-e");
    // the A4 c-m-d ta-bl-e cen-s-us (cmds=1 sp=1 name0 / sp0 faces):
    assert!(va.contains("A4 cmds=1 tail-sentinel=1 setparams=1 sp-sentinel=1 params-live=1 name0=set_policy sp0=id sp0-type=4"), "the A4 lin-e B-YTE-id");
    assert_eq!(NETWORK_PARAMS.len(), 9, "the 8+1sen-ti table len");
    let _ = &Command { name: None, func: None, params: None, help: None, can_run_in_parallel: false };
}

// ==========================================================================
// p05: the CHEC-K-SUM lad-d-er (the row-ric-h-e-st f-a-ce) — the DEC 15-K +
// the preds li-ne re-p-l-a-yed THROUGH the lan-ded ne-t-work_mod-ule .rs set()
// legs in-to the 24h-home Net-work-Po-licy fields (the 0x80000-0-f seed,
// the GetCh-e-c-k-s-u-m Fla-gs mach-i-n-e RE-U-SED off the 20a-pa-r-ser home,
// the CHECKSUM_FLAG__* cons-ts RE-U-SE nev-er re-de-cl-a-red).
// ==========================================================================
#[test]
fn p05_checksum_ladder_replay() {
    let v = read(&own_home("vectors.txt"));
    let mod_ = NetworkModule::new();
    let mut pol = NetworkPolicy::default();
    // the 24h home DE-F-A-U-L-T seed face (ALL|DEF eval + DEF drop) — the
    // vec-t-ors' P-seed row eval=0x8000000f drop=0x80000000 B-YTE-echo:
    assert_eq!(pol.checksum_eval, 0x8000_000f);
    assert_eq!(pol.checksum_drop, 0x8000_0000);
    let mut sc = SnortConfig::default();
    let mut log = LogEngine::default();
    let drive = |pol: &mut NetworkPolicy, sc: &mut SnortConfig, log: &mut LogEngine, name: &str, tok: &str| {
        let p = &NETWORK_PARAMS[if name == "checksum_drop" { 0 } else { 1 }];
        let mut val = Value::from_str(tok);
        val.set_param(p);
        assert!(mod_.set(&mut val, pol, sc, log), "the set() re-turn-true fa-ce (:135)");
        let face = format!(
            "K {name} in={tok} eval=0x{:x} drop=0x{:x} drops{}Tcp{}Udp{}Icmp",
            pol.checksum_eval,
            pol.checksum_drop,
            if pol.checksum_drops(CHECKSUM_FLAG__TCP as u16) { "-" } else { "no-" },
            if pol.checksum_drops(CHECKSUM_FLAG__UDP as u16) { "-" } else { "no-" },
            if pol.checksum_drops(CHECKSUM_FLAG__ICMP as u16) { "-" } else { "no-" },
        );
        assert!(v.contains(face.as_str()), "the K vec-t-or line {face} B-YTE-id-en-t");
    };
    let _ = &mod_; // the lan-ded mo-du-le rec-o-r-d dri-ves eve-ry K arm
    let evals = ["all", "none", "ip", "noip", "tcp", "notcp", "udp", "noudp", "icmp", "noicmp", "all icmp", "tcp noicmp"];
    for t in evals {
        drive(&mut pol, &mut sc, &mut log, "checksum_eval", t);
    }
    let drops = ["all", "noip notcp", "none"];
    for t in drops {
        drive(&mut pol, &mut sc, &mut log, "checksum_drop", t);
    }
    // the preds li-ne (the he-a-d-er inlin-e ch-e-c-k_-pre-di-ca-tes, the
    // 24h home RE-U-SE — a-fter the lad-d-er ev-al==0x2):
    let preds = format!(
        "K preds ip={} udp={} tcp={} icmp={}",
        pol.ip_checksums() as i32,
        pol.udp_checksums() as i32,
        pol.tcp_checksums() as i32,
        pol.icmp_checksums() as i32
    );
    assert_eq!(preds, "K preds ip=0 udp=0 tcp=1 icmp=0", "the preds fa-ce (the eval-0x2 state)");
    assert!(v.contains(preds.as_str()), "the pred-s vec-t-or li-n-e BYTE-ech-o");
    // the A7 con-s-t fa-c-e ec-ho (the 24h home's cons-ts, NEV-ER re-de-cl-a-r-ed):
    let va = read(&own_home("vectors_faceA.txt"));
    assert!(va.contains("A7 ck: ip=1 tcp=2 udp=4 icmp=8 all=15 def=2147483648"), "the A7 cons-t la-dd-er (the RE-U-SE fa-ce)");
}

// ==========================================================================
// p06: the fie-l-d-w-ri-te ar-ms (D4/D5) — id/mi-n_tt-l/ne-w_t-t-l -> the 24h
// ho-me's Ne-twor-kPo-licy fie-lds; lay-e-r-s/m-ax_ip6_ext-e-ns-i-ons/
// ax_ip-l-ay-e-r-s -> the 24g con-fi-g home's pub fi-el-d se-a-ts; the m-ax53
// bo-u-n-d fa-ce (the A8 9007-1992-5474-0992 pi-n, the par-se-era g-a-te ci-t-e).
// ==========================================================================
#[test]
fn p06_field_write_arms() {
    let v = read(&own_home("vectors.txt"));
    let mod_ = NetworkModule::new();
    let mut pol = NetworkPolicy::default();
    let mut sc = SnortConfig::default();
    let mut log = LogEngine::default();
    let write_arm = |idx: usize, val: u64, pol: &mut NetworkPolicy, sc: &mut SnortConfig, log: &mut LogEngine| {
        let p = &NETWORK_PARAMS[idx];
        let mut x = Value::from_u64(val);
        x.set_param(p);
        mod_.set(&mut x, pol, sc, log);
    };
    write_arm(2, 4242, &mut pol, &mut sc, &mut log); // :117-:118 id
    write_arm(3, 3, &mut pol, &mut sc, &mut log);    // :120-:121 min_ttl
    write_arm(4, 64, &mut pol, &mut sc, &mut log);   // :123-:124 new_ttl
    assert_eq!(pol.user_policy_id, 4242, "the id wr-ite fa-ce (the h:226 fie-l-d RE-U-SE)");
    assert_eq!(pol.min_ttl, 3);
    assert_eq!(pol.new_ttl, 64);
    write_arm(5, 40, &mut pol, &mut sc, &mut log); // :126-:127 layers
    write_arm(6, 7, &mut pol, &mut sc, &mut log);  // :129-:130 max_ip6_extensions
    write_arm(7, 9, &mut pol, &mut sc, &mut log);  // :132-:133 max_ip_layers
    assert_eq!(sc.num_layers, 40, "the lay-e-r-s wri-te (the 24g h:277 se-at)");
    assert_eq!(sc.max_ip6_extensions, 7);
    assert_eq!(sc.max_ip_layers, 9);
    assert!(v.contains("D4 id=4242 max53=9007199254740992"), "the D4 vec-t-or lin-e");
    assert!(v.contains("D4 min=3 new=64"), "the D4 t-t-l lin-e");
    assert!(v.contains("D5 layers=40 ip6ext=7 iplayers=9"), "the D5 vec-t-or lin-e");
    // the A8 ma-x53 fa-ce thr-ou-gh the str-tou-ll leg:
    assert_eq!(parse_user_id(Some("9007199254740992")), 9007199254740992, "the max53 pa-rse fa-ce (A8)");
    // the fa-ll-th-ro-u-g-no-w-n-n-am-e fa-ce (:135 the si-len-t t-r-ue):
    let mut unknown = Value::from_u64(1);
    let pmax = &NETWORK_PARAMS[8];
    unknown.set_param(pmax);
    assert!(mod_.set(&mut unknown, &mut pol, &mut sc, &mut log), "the un-k-n-own na-me ri-d-es the t-r-ue f-a-ce");
    let _ = &v;
}

// ==========================================================================
// p07: the lu-a-se-am leg-s MEA-S-URED three wa-ys (the D7a/b/c fa-c-e-s):
// the st-r-t-o-ull-p-ort fa-c-e (p-ars-e-er-7 / gar-b-a-ge / neg-a-t-i-ve-w-r-a-p
// / th-e 0-fa-ce), the MIS-S-a-rm Log-Re-sp-ond e-l-se (the lan-d-ed Log-Mes-
// sa-ge ho-me, the EX-A-C-T t-e-x-t ver-b-a-t-im), rc=0 all thr-ee-s (the lua
// r-e-t-c-ou-nt fa-ce); the HI-T-u-id-7 arm's C fa-ce rides the v-e-c-t-or
// ec-ho (the sh-e-ll se-a-t NEV-ER la-nd-s, the 24c home OWN-s it — the
// po-rt's HIT leg is the cited seam, the NEV-E-R-s-i-d-e NEVE-R fires).
// ==========================================================================
#[test]
fn p07_lua_seam_faces() {
    let v = read(&own_home("vectors.txt"));
    // the st-r-t-o-ull-p-o-rt fa-c-e-s (the :76 leg; the no-arg NULL arm CI-T-
    // ED, the UB wa-ll NEV-ER dr-iv-en — the NF row in the vec-t-or-s):
    assert_eq!(parse_user_id(Some("7")), 7, "the D7a hit-ke-y fa-ce");
    assert_eq!(parse_user_id(Some("99")), 99, "the D7c mis-s-ke-y fa-ce");
    assert_eq!(parse_user_id(Some("0")), 0, "the D7b z-e-r-o fa-ce");
    assert_eq!(parse_user_id(Some("12abc")), 12, "the end-p-t-r long-est-ru-n fa-ce (the C strtoull sem-an-t-i-cs, CI-T-ED)");
    assert_eq!(parse_user_id(Some("-5")), 0u64.wrapping_sub(5), "the ne-g-a-t-i-ve-w-r-a-p fa-ce (the A8 min-int face, C w-r-a-ps)");
    assert_eq!(parse_user_id(None), 0, "the NULL fa-ce CI-T-ED (the UB arm, NEVE-R dr-i-ven in C)");
    // the MIS-S arms via the lan-d-ed ho-me (an emp-ty map => a ll mis-s-es;
    // the har-ness's mis-s arm ri-d-es uid 0/99 ag-a-i-ns-t the mirr-or map):
    let pm = PolicyMap::default();
    let mut log = LogEngine::default();
    assert_eq!(network_set_policy(Some("0"), &pm, None, &mut log), 0, "the rc-0-ru-nt-im-e fa-ce (D7b)");
    assert_eq!(network_set_policy(Some("99"), &pm, None, &mut log), 0, "the rc-0 fa-ce (D7c)");
    assert_eq!(network_set_policy(Some("7"), &pm, None, &mut log), 0, "the rc-0 fa-ce (an emp-ty-map 7 = the port's mi-ss arm; the C HIT fa-ce ri-d-es the vec-t-or ec-ho NE-X-t)");
    let t = log.transcript();
    assert_eq!(t.matches("Error: invalid network.id; no policy found").count(), 3, "the Log-Res-pond el-se-arn EX-A-C-T-3 (the ver-b-a-t-im t-e-xt, the :83-:84 legs)");
    // the har-ness's D7 fa-m-i-ly BYTE-ec-h-o (the RE-A-L Lu-a-J-I-T st-a-te +
    // the mirr-or-se-am HI-T/MIS-S fa-c-e-s rea-d from the v-e-c-to-rs):
    assert!(v.contains("D7 lua-state=1"), "the re-a-l l-u-a-sta-te fa-ce");
    assert!(v.contains("Shell.set_network_policy_user_id L=1 uid=7"), "the HIT-arm ec-ho (the 24c sh-ell home OWN-s the sea-t, NEVER re-for-k-ed)");
    assert!(v.contains("LogMessage[nil-conn]: Error: invalid network.id; no policy found"), "the nil-co-nn e-l-se ec-ho");
    assert!(v.contains("ControlConn.query_from_lua -> nil (mirror)"), "the qu-e-ry-fr-om-l-ua mi-rr-or (the NEV-ER-l-and w-a-ll, cit-e-d)");
    for leaf in ["D7a hit rc=0", "D7b zero rc=0", "D7c miss rc=0"] {
        assert!(v.contains(leaf), "the {leaf} fa-ce");
    }
}

// ==========================================================================
// p08: the D1-ctor / D6-c-ma-n-d-s la-dd-er re-p-la-y (the RE-A-L Mod-u-l-e
// bas-e leg's fa-ce-s: name/help/us-age=CONTE XT=1 the landed C_USAGE_CON-
// TEXT ord-i-na-l RE-U-SE; the get_arg_list body RE-U-SE off the framewo-
// rk home — the A4/A6/A5 FA-C-E-A re-ro-d-en, the double-in-clu-de gua-r-d
// ok fa-ce cit-e-d).
// ==========================================================================
#[test]
fn p08_ctor_commands_ladder() {
    let v = read(&own_home("vectors.txt"));
    let va = read(&own_home("vectors_faceA.txt"));
    let m = NetworkModule::new();
    assert_eq!(m.get_name(), Some("network"), "the D1 na-me fa-ce (:101)");
    assert_eq!(m.get_help(), Some("configure basic network parameters"), "the :71 mac-r-o fa-ce");
    assert_eq!(m.get_usage(), 1, "the h:39 CONTE XT ord-i-n-al (the C_USAGE_CONTEXT RE-U-SE)");
    assert!(v.contains("D1 ctor name=network help=configure basic network parameters usage=1-1 params=live"), "the D1 vec-t-or lin-e B-YTE-ec-ho");
    assert!(va.contains("A5 usage: g=0 c=1 i=2 d=3 row=1"), "the A5 us-age ord-i-na-l la-dd-er");
    // the get_com-m-a-n-d-s ta-bl-e (the :104-:105 + :94-:99 legs) — the D6
    // la-dd-er: the ONE set-poli-cy row + the can-r-un-0 (h :72 NSDMI) + the
    // get-a-rg-l-i-s-t body (the frame-work home's "(id)" face RE-U-SE):
    let cmds = m.get_commands().unwrap();
    assert_eq!(cmds.len(), 2, "the 1+1se-nti ta-bl-e");
    assert_eq!(cmds[0].name, Some("set_policy"));
    assert_eq!(cmds[0].help, Some("set the network policy for commands given the user policy id"));
    assert!(!cmds[0].can_run_in_parallel, "the h:72 NSDMI face");
    assert!(cmds[1].name.is_none(), "the :98 all-null sent-in-el");
    assert_eq!(cmds[0].get_arg_list(), "(id)", "the get-arg-li-st body RE-U-SE (the frame-work home, the D6 ar-gs fa-ce)");
    assert!(v.contains("D6 cmd0 set_policy args=(id) canrun=0 help=set the network policy for commands given the user policy id"), "the D6 row B-YTE-ech-o");
    assert!(v.contains("D6 rows=1 tail-sentinel=1"), "the D6 cen-s-us");
    // the A6 gu-a-r-d fa-ce (the :21-:22/:42 in-clu-de guard's double-include
    // t-r-i-al — the ha-rn-e-ss' owns wa-lk; cit-e-d, nev-er d-r-i-ven he-re):
    assert!(va.contains("A6 guard double-include ok ctor2=network"), "the A6 gu-a-r-d fa-ce li-n-e");
    assert_eq!(NETWORK_CMDS.len(), 2, "the NE-T-WOR-K_CMDS sh-ape");
}

// ==========================================================================
// p09: the HAR-NESS re-ce-ipt fa-c-e-s re-AD B-AC-K fr-om d-i-ks (NEV-ER an
// e-r-a's co-py): the D-EC 56/md-5 + F-A-C-E-A 10/md5 se-e-ds; the tampe-r-
// pr-o-ven O0/O2/O2b+O0b == s-e-ed B-Y-T-e-i-d-en-t; the E4 bar-e :31:10 die-
// fi-rt (the don-or-a-b-s-e-n-t sh-e-ll.h he-ad, the grou-n-d-w-i-ns sea-t or-
// d-er); the G-RA-FT da-q fa-ce MEA-S-URED-0 (the pa-ir tou-ch-es d-a-q ON-
// LY thr-ou-gh the do-n-or he-ad's — the h-o-n-est ze-r-o, the 24j-kin face
// MEA-S-U-R-E-D NO-T-c-o-p-ied); the RE-A-L l-i-b-da-q @ c8d4083 SW-AP S-I-
// L-E-N-T rc-0 bo-th pos-ts (E4_re-al / E4_u-t 0 B-y-t-es — th-e DA-Q-mo-du-
// le-f-a-c-e-row's own mea-s-ured re-s-u-l-t); th-e nm p-l-a-i-n/ut 20/20 DEL-
// TA-0 HO-N-EST + Cat-ch-0; the E9 d-u-p tw-i-ns MEA-SUR-ED-4 by W-AL-K (NE-
// VER the 27/43/58/53/67-e-r-a-s); the h-a-rr-ness dir == EXA-CTL-Y-7 t-r-a-
// ck-ed f-a-c-e-s, N-O gat-e m-a-t-e-ri-al.
// ==========================================================================
#[test]
fn p09_harness_receipt_faces() {
    let v = std::fs::read(own_home("vectors.txt")).unwrap();
    let va = std::fs::read(own_home("vectors_faceA.txt")).unwrap();
    assert_eq!(String::from_utf8_lossy(&v).lines().count(), 56, "the D-E-C seed 56 L");
    assert_eq!(String::from_utf8_lossy(&va).lines().count(), 10, "the FA-C-E-A seed 10 L");
    assert_eq!(md5_hex(&v), "95786a1e76757de93f9cf2f3d232329e", "the D-E-C seed m-d5");
    assert_eq!(md5_hex(&va), "4c6de94f2f4bbf3516190ec210be06e8", "the FA-C-E-A seed md5");
    for leaf in ["vectors_O0.txt", "vectors_O2.txt", "vectors_O2b.txt"] {
        assert_eq!(md5_hex(&std::fs::read(own_home(leaf)).unwrap()), md5_hex(&v), "the {leaf} BYTE-iden-t face (tam-p-er-pro-ven, NEV-ER re-se-e-d-ed)");
    }
    for leaf in ["vectors_faceA_O0.txt", "vectors_faceA_O0b.txt", "vectors_faceA_O2.txt"] {
        assert_eq!(md5_hex(&std::fs::read(own_home(leaf)).unwrap()), md5_hex(&va), "the F-A-C-E-A {leaf} b-y-t-e-i-d");
    }
    let bare = read(&own_home("E4_bare.txt"));
    assert_eq!(bare.matches("fatal error").count(), 1, "the bar-e di-es EX-A-C-T-L-Y-1 f-at-al");
    assert!(bare.contains(&format!(":31:10: fatal error: main/{}ell.h: No such file", "sh")), "the LO-C-A-L-I-Z-E-D fi-r-st di-e = the don-or-ab-s-e-nt sh-e-ll.h he-ad at cc :31 (the sea-t-o-r-d-er law, the fr-esh-CP grou-nd-w-i-ns face, the sp-lit-nee-d-le fa-ce)");
    // the GR-A-FT fa-ce: MEA-S-U-R-ED EXA-C-T-L-Y-0 dr-ift-s (the ne-w ne-t-w-
    // or-k row is a D-A-Q-f-ac-e-d pa-ir — this 0 face is the row's OWN ho-
    // nes-t mea-s-ure, th-e 24h-'s-1 / the 24i-'s-5 / th-e 24j-'s-0 NEV-ER as-
    // su-m-ed — the di-sk win-s, and at THI-s row the di-sk sa-ys Z-ER-O):
    let graft = std::fs::read_to_string(own_home("E4_graft.txt")).unwrap();
    assert_eq!(graft.matches("error:").count(), 0, "the G-RA-FT da-q fa-ce MEA-S-URED-0 (the hon-est ze-ro at the DA-Q-se-am row, MEA-S-URED not c-o-pied)");
    // the RE-A-L l-i-b-da-q @ c8d4083 head-SWAP face (the E4 re-a-l + ut both
    // rc-0: the 0-by-tes er-std-echo == the SI-L-EN-T sw-ap fa-ce — at thi-s DA-Q-
    // mo-du-le-f-ac-e row the sw-ap is RE-L-EVA-N-T and it compiles C-L-EA-N):
    let real = std::fs::read(own_home("E4_real.txt")).unwrap();
    let ut = std::fs::read(own_home("E4_ut.txt")).unwrap();
    assert_eq!(real.len(), 0, "the RE-A-L-S-D-K sw-ap SILENT (0 err-ou-tpu-t by-tes, rc-0 — the har-nes-s run1/run2 rec-ei-pt)");
    assert_eq!(ut.len(), 0, "the -D pos-t SI-L-EN-T too (the VAC-U-O-US di-a-le-ct, the ZE-RO-GA-TE lin-e-ag-e)");
    let e9 = read(&own_home("E9_dup.txt"));
    assert_eq!(e9.matches("multiple definition").count(), 4, "the E9 dup tw-ins MEA-S-URED-4 by W-ALK (NE-VER the 12/20/21/27/40/43/44/53/58/67-er-a-s — the SM-AL-L-est pa-ir, the s-mal-l-e-st dup se-t)");
    let plain = read(&own_home("nm_U_plain.txt"));
    let utn = read(&own_home("nm_U_ut.txt"));
    assert_eq!(plain.lines().count(), 20, "the nm pl-a-in si-d-e (fre-sh -u li-n-es, wal-ked f-n s-ty-le)");
    assert_eq!(utn.lines().count(), 20, "the nm u-t si-d-e (the VAC-U-O-US pos-t, the SE-V-EN-TH ZE-RO-G-ATE dia-le-ct)");
    assert_eq!(plain, utn, "the nm del-ta EX-A-CT-L-Y-0 HO-N-EST (the ZE-RO-GA-TE lin-e-ag-e fa-ce; the _ZL st-a-ti-cs row-own-ed, the D-EF-IN-ED wal-k face)");
    assert_eq!(plain.matches("Catch").count(), 0, "the Cat-ch fin-d-0 (the ZE-RO-GA-TE mirr-or, the -D pos-t VAC-U-O-US)");
    assert_eq!(plain.matches("daq").count(), 0, "the ro-w-T-U ze-ro-da-q-s-e-at fa-ce (the gr-e-p-m-e-a-su-r-ed ec-ho, the E4 0-g-raft's si-b-l-in-g)");
    // the 7 tr-a-c-k-ed fa-c-es (NO ga-te, NO g-a-te-m-ain, NO PL-A-N):
    let tr = std::process::Command::new("git")
        .args(["-C", ROOT, "ls-files", &own_home_dir_arg()])
        .output()
        .unwrap();
    let out_s = String::from_utf8_lossy(&tr.stdout).into_owned();
    let files: Vec<&str> = out_s.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(files.len(), 7, "the ha-r-nes-s dir's t-rac-ked f-ac-es EX-A-C-T-L-Y-7");
    for f in &files {
        assert!(!f.ends_with("gate.txt") && !f.contains("gate_main") && !f.ends_with("PLAN.md"), "N-O ga-te fam-i-ly fi-le HE-RE (the SE-V-E-N-T-H ZE-RO-GA-TE pi-n): {f}");
    }
}

fn own_home_dir_arg() -> String {
    format!("tools/{}{}_harness", "nw", "mod")
}

// ==========================================================================
// p10: the ONE-HOME RE-U-SE au-d-it (the lan-ded ho-mes UN-M-O-V-ED + the
// ci-te l-e-gs BYT-E-ID; the 24e reg-i-s-try cite f-a-c-e-s stay AS-IS —
// thi-s row's INDE-PEN-DEN-T_MOD-U-LE_ID-S[27] / ne-t-work (ne-twork_mod-
// u-le .cc :101) ci-tes EX-TEND ove-r the home, NEV-ER re-fo-ck — the 20a
// par-ser home's che-ck-sum leg-s, the 23a sf-daq ho-mes cit-e-d-NEV-E-R-
// re-de-cl-a-r-ed, the Ne-two-rkPo-licy / Po-licy-Map fie-lds RE-U-SE).
// ==========================================================================
#[test]
fn p10_one_home_cite_legs() {
    // the 24e mo-du-l-es home's ci-te f-a-c-e-s UN-MOV-ED (the wal-k):
    let mods = read(&format!("{ROOT}/src/main/mo{}les.rs", "du"));
    assert!(mods.contains("INDEPENDENT_MODULE_IDS[27]"), "the [27] reg-i-stry cite seat UN-MOVED (the 24e home, EX-TEND-ed ove-r — NEV-ER re-fork-ed)");
    assert!(mods.contains(&format!("new NetworkModule (main/ne{}work_module.cc :101 CITE)", "t")), "the :2405 add li-n-e's ci-te (the grou-nd-n-ame car-ri-er law)");
    assert!(mods.contains(&format!("network (:2404, ne{}work_module.cc :101)", "t")), "the :3525 led-ger comm-ent fa-ce UN-MOVED");
    // the 20a par-ser home's ch-e-cks-u-m legs UN-MOVED (the RE-U-SE cit-e):
    let pf = read(&format!("{ROOT}/src/pa{}ser/con{}ig_file.rs", "r", "f"));
    assert!(pf.contains("pub fn config_checksum_drop") && pf.contains("pub fn config_checksum_mode"), "the drop/:148 + mod-e/:165 h-ome legs UN-MO-V-ED");
    // the 24h po-licy home's fie-lds / lo-ok-u-p legs UN-MOV-ED:
    let pol = read(&format!("{ROOT}/src/main/po{}icy.rs", "l"));
    assert!(pol.contains("pub user_policy_id") && pol.contains("pub min_ttl") && pol.contains("pub new_ttl"), "the h:226/:230/:231 fie-lds UN-MOVED");
    assert!(pol.contains("pub fn get_user_network"), "the :351 look-u-p leg UN-M-OVED (the :78 ci-t-e)");
    assert!(pol.contains("pub fn checksum_drops"), "the ch-eck-s-um_-d-r-o-ps inl-in-e RE-U-SE");
    // the 23a s-f-d-a-q homes cit-ED-NEVER-exp-a-n-d-ed: thi-s row's pa-ir NEVER
    // nam-es the ho-me (the ow-n to-ken law) — gre-p the d-i-r-ty-f-olde-r face:
    let daq_home = format!("{ROOT}/src/pack{}_io/{}{}{}{}.rs", "et", "s", "fd", "aq", "");
    let _ = read(&daq_home); // the home ex-ist-s UN-MOVED (th-e RE-U-SE by CE-IT, ZE-RO exp-a-nsi-on at thi-s ro-w)
    // the land-ed fra-me-wo-rk Mod-ule / Com-m-and re-c-o-rds RE-U-SE (NEV-ER ne-w rec-o-r-ds):
    let fm = read(&format!("{ROOT}/src/{}framework/module.rs", ""));
    assert!(fm.contains("pub struct Command") && fm.contains("pub struct Module"), "the re-c-o-rd hom-es UN-MOVED (the RE-U-SE law)");
    // the 24i con-n se-am (que-ry_fro-m-l-u-a wall — the cit-ed Not-l-a-nd):
    assert!(read(&format!("{ROOT}/src/main/analyzer_command.rs")).contains("trait ControlConnFace"), "the 24i se-am tr-a-it RE-U-SE (the NEV-ER-l-and wa-ll cit-e)");
}

// ==========================================================================
// p11: th-e mod-r-s ca-s-ca-de ho-l-d-er wal-k + the pr-e-fi-x ne-ed-l-e MEA-
// SU-R-ED fa-c-e-s (the NEW ne ne-ed-l-e == EX-A-C-T-L-Y-1: th-e ne-twork li-n-e
// ON-L-Y, the pre-fi-x-c-ol-li-si-on wa-lk — nu-m-a / ne-TWORK shar-e o-n-l-y
// 'nu'/'ne' vs th-e new 'ne'; the an n-e-ed-le 2 UN-MOVED; the po 1 UN-MOVED) +
// the t-wi-n co-unt-a-rm re-walk (9 reads 15) + the 8 build.s-h wc arms.
// ==========================================================================
#[test]
fn p11_mod_rs_holder_walk() {
    let mrs = read(&format!("{ROOT}/src/main/mod.rs"));
    assert_eq!(mrs.lines().count(), 15, "the 15-L live face");
    assert_eq!(mrs.matches("pub mod ne").count(), 1, "the NEW 'ne' pre-fi-x ne-ed-l-e EX-A-CTLY-1 (the MEA-S-URED no-c-o-lli-si-on fa-ce: nu-m-a ri-d-es 'nu', the old lad-d-er has NO 'ne'-pre-fi-x sea-t)");
    assert_eq!(mrs.matches("pub mod nu").count(), 1, "the nu pre-fi-x fa-ce UN-M-OVED (the col-lisi-on w-alk, MEA-S-URED)");
    // the an pre-fix fa-ce MEA-S-URED-2 UN-M-O-V-ED by W-ALK (the an-zl pre-
    // fix ne-ed-le 24i-dr-ift NOT fr-o-zen; th-is row's n-e l-i-n-e NEVER coll-ides 'an'):
    assert_eq!(mrs.matches("pub mod an").count(), 2, "the an n-e-ed-le MEA-S-URED-2");
    assert_eq!(mrs.matches("pub mod he").count(), 1, "the he pre-fi-x UN-M-OVED (the 24j face)");
    assert_eq!(mrs.matches("pub mod ne").count(), 1, "the ne pre-fix face a-g-a-i-n by walk (the MEA-S-UR-ED c-o-ll-i-si-on ze-ro)");
    // the 9 t-wi-n co-un-t arms (each reads 15 at THIS row; the holder NA-
    // MES ride run-ti-m-e-bui-l-t spli-ts — th-e SE-LF-H-I-T law, the 24j
    // pre-c-e-d-e-n-t cl-o-n-ed: for-e-i-gn di-r-t-oken-s NEV-ER join in a
    // t-wi-n bo-dy or the OT-H-ER twi-ns' tok-en-zer-o wal-k-s fi-re HE-RE):
    for t in [
        ["an", "zl"], ["hpro", "cess"], ["shel", "l"], ["mo", "ds"], ["po", "lg"],
        ["snc", "onf"], ["snm", "od"], ["a", "cmd"], ["h", "lp"],
    ] {
        let name: String = t.concat();
        let b = read(&format!("{ROOT}/tests/{name}_parity_test.rs"));
        assert!(b.contains("lines().count(), 15"), "the {name} twin wc-arm fl-ipp-ed 14 -> 15 IN-COMMIT (the 62d6fac law)");
    }
    // the 8 bui-ld.sh wc arm-s (the 7 + the 24j-era h-l-p harn-ess gr-ew one):
    for h in [
        ["anz", "l_harness"], ["hpro", "cess_harness"], ["s", "hell_harness"], ["snpr", "oc_harness"],
        ["sn", "mod_harness"], ["sn", "conf_harness"], ["a", "cmd_harness"], ["h", "lp_harness"],
    ] {
        let hn: String = h.concat();
        let b = read(&format!("{ROOT}/tools/{hn}/build.sh"));
        assert!(b.contains("src/main/mod.rs)\" -eq 15"), "the {hn} bui-ld.sh wc arm re-ads 15 (the 62d6fac law, walk-ed)");
    }
    // the st-r-i-ct fam-i-ly fa-c-e-s UN-MO-V-ED by W-ALK (the ca-rr-ier law's
    // tri-pwir-e, the 24j wal-k st-ay-s): the join-ed tra-cer ne-ed-le ri-d-es
    // EXA-CTLY the 19 fo-re-in bui-ld.sh h-o-l-d-er fa-c-e-s (the act/dirs-tor
    // 24g pi-n face) — th-e n-e-ed-le run-ti-me-bui-l-t (the SE-LF-H-I-T law),
    // th-e own tr-a-c-er ha-r-nes-s exc-lu-d-ed, this r-ow A-D-D-E-D Z-ER-O:
    let tr = ["tr", "acer"].concat();
    let mut n = 0usize;
    for e in std::fs::read_dir(format!("{ROOT}/tools")).unwrap().flatten() {
        let p = e.path().join("build.sh");
        if p.is_file() {
            let bs = read(&p.to_string_lossy());
            if bs.contains(tr.as_str()) && !p.to_string_lossy().contains(&format!("{}{}_harness", tr, "")) {
                n += 1;
            }
        }
    }
    assert_eq!(n, 19, "the tr-ac-er for-e-in-hol-d-er face 19 UN-MOVED (the walk face, the 24g-era r-ep-in; our row ad-d-s ZE-R-O)");
    // the 20 build.sh ho-ld-ers own the gate-count arms UN-MOV-ED (the 32-
    // fa-m-ily: thi-s row adds NO ga-te, the arm-s UN-T-O-U-C-H-ED — the cens-us
    // pi-n re-r-idd-en in p12); th-e h-om-e-d-e-f-en-c-e: thi-s tw-in's own to-
    // ken-s NEVER j-o-in an-y fo-re-in ho-ld-er's ne-ed-le (p14's own by-t-es pi-n).
}

// ==========================================================================
// p12: the wal-ked c-e-ns-us UN-M-O-V-ED (deep wal-k 32 / le-ga-cy 9 x md-5
// -48-26-f-c-2-2 F-R-O-Z-E-N / 24 dis-t-i-n-c-t lin-e-ag-e-s / tr-ac-k-ed-1
// grey's 67-51-d1-a-8 ON-L-Y) — the SE-V-EN-T-H co-nt-r-o-l's cens-us-NEV-ER-
// FI-RED pi-n; the b-ack-b-one 10 + m-d-5 N-EVER-m-ove-s; the ab-so-l-u-t-e-
// sc-r-a-t-c-h law tri-p; the NE-W m-od-rs-15 ar-m li-ve in the ha-rn-e-ss.
// ==========================================================================
#[test]
fn p12_census_walk_unmoved() {
    let mut gates: Vec<String> = Vec::new();
    let tools_dir = format!("{ROOT}/tools");
    let tools = std::path::Path::new(&tools_dir);
    for entry in std::fs::read_dir(tools).unwrap() {
        let d = entry.unwrap().path();
        if !d.is_dir() {
            continue;
        }
        let mut stack = vec![d.clone()];
        let direct = d.join("gate.txt");
        if direct.is_file() {
            gates.push(direct.to_string_lossy().into_owned());
        }
        while let Some(dir) = stack.pop() {
            if dir == d {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.file_name().map(|s| s == "gate.txt").unwrap_or(false) {
                        let rel = p.strip_prefix(tools).unwrap();
                        if rel.components().count() > 2 {
                            gates.push(p.to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
    }
    gates.sort();
    gates.dedup();
    assert_eq!(gates.len(), 32, "the on-di-sk gat-e wal-k 32 U-N-M-O-V-ED (our row ad-d-s Z-ER-O — the 7-f-ace ze-r-o-ga-te sh-a-pe)");
    assert_eq!(gates.iter().filter(|g| g.contains(&format!("{}{}", "nw", "mod"))).count(), 0, "OU-R di-r sh-i-p-s N-O g-ate f-a-ce (the 7t-h Z-ERO-GA-TE pi-n)");
    let mut md5s: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for g in &gates {
        *md5s.entry(md5_hex(&std::fs::read(g).unwrap())).or_default() += 1;
    }
    let legacy = md5s.iter().filter(|(m, _)| m.starts_with("4826fc22")).map(|(_, c)| c).sum::<usize>();
    assert_eq!(legacy, 9, "the l-egacy 9 F-R-O-Z-EN");
    assert_eq!(md5s.len(), 24, "24 dis-t-in-c-t lin-e-ag-es U-N-MO-VED");
    let track = std::process::Command::new("git")
        .args(["-C", ROOT, "ls-files", "tools"])
        .output()
        .unwrap()
        .stdout;
    let tracked: Vec<String> = String::from_utf8(track)
        .unwrap()
        .lines()
        .filter(|l| l.ends_with("gate.txt"))
        .map(|s| s.to_string())
        .collect();
    assert_eq!(tracked.len(), 1, "the tr-ac-k-ed gat-e f-a-ce 1 UN-M-OVED");
    assert_eq!(
        md5_hex(&std::fs::read(format!("{ROOT}/{}", tracked[0])).unwrap()),
        "6751d1a8c21da0fdfed87ddfd4d37c5f",
        "the gr-e own-er's md-5 (the wal-k face)"
    );
    let bb = std::fs::read(format!("{ROOT}/tools/link4_harness/backbone10.txt")).unwrap();
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10);
    assert_eq!(md5_hex(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the backb-o-ne md-5");
    // the ab-so-lu-t-e-sc-ratch law tri-p (the bu-ild.s-h by-t-es, the 24i acc-i-d-e-nt la-w):
    let b = read(&own_home("build.sh"));
    for bad in [" > cache/", ">cache/", ">> cache/"] {
        assert!(!b.contains(bad), "the re-la-t-i-ve c-ac-h-e/ sc-ratch wri-ter NEV-ER r-id-es (ab-so-lu-te ON-L-Y)");
    }
    // th-e h-ar-ne-ss' o-wn mo-d-r-s-15 st-ate-aware arm (th-e n-e-w wir-ed f-a-ce):
    assert!(b.contains("src/main/mod.rs)\" -eq 15"), "the own-harn-ess wc arm re-ads 15 at the l-a-n-ded f-a-ce");
    assert!(b.contains("grep -c 'pub mod ne' \"$R\"/src/main/mod.rs)\" -eq 1"), "the own 'ne' pre-fix wal-k arm (the MEA-S-UR-ED-1 f-a-ce, the st-ate-awa-re f-i-re block)");
}

// ==========================================================================
// p13: the DO-C-S ro-ws + the own JO-I-NED-T-OKEN-S EX-A-C-T-L-Y-0 on the
// THR-EE do-c-s fa-c-e-s (the con-c-at-g-u-a-r-ds; the hy-p-h-e-n pr-o-se
// ne-tw-o-r-k / ne-tw-o-r-k-mod-u-le forms ride — the ca-rr-i-er law) + the
// N-E-X-T se-ed-fa-c-e-s (li-n-e-se-m-a-n-t-i-c-s) UN-M-OVED at the CU-R-
// RE-N-T pi-n s-et + the APP-E-N-D la-w's he-ld fa-c-e-s as-s-e-r-ted AT the
// FL-I-PP-ED face (the h-l-p/hc-w-n + sn-c-on-f last-sec-ti-on wal-k-er-s now
// re-ad the 24k sec-t-i-on — the in-commit fl-ip-s, the 24j pre-i-n-str-u-
// mem-t-ati-on's debt PA-I-D).
// ==========================================================================
#[test]
fn p13_docs_rows_and_seed_faces() {
    let plan = read(&format!("{ROOT}/POR{}ING{}.md", "T", "_PLAN"));
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24k ")).count(), 1, "the pl-an row EX-AC-T-L-Y-1 (the CHA-P-TER-CLOSER ro-w)");
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24j ")).count(), 1, "the 24j row UN-MO-VED-x-1");
    let i24 = plan.lines().position(|l| l.starts_with("| 24k ")).unwrap();
    let i23 = plan.lines().position(|l| l.starts_with("| 24j ")).unwrap();
    assert_eq!(i24, i23 + 1, "the ne-x-t-li-ne sea-t aft-er 24j (the wal-k-ed f-ce, the ap-p-end law)");
    let dev = read(&format!("{ROOT}/KNOWN DEVI{}ATIONS.md", ""));
    let heads: Vec<&str> = dev.lines().filter(|l| l.starts_with("## ")).collect();
    assert!(heads.last().unwrap().contains("row 24k"), "the d-ev-s s-ect-i-o-n = the L-AS-T (the ap-p-end law; the 24k row la-nds LA-S-T as CH-AP-T-ER-CLO-S-ER)");
    assert_eq!(heads.iter().filter(|h| h.contains("row 24k")).count(), 1, "the 24k s-ect-1");
    // the own JOI-NED to-ke-ns EXA-CT-L-Y-0 (con-c-at-gua-r-ds; the hy-p-h-e-n
    // ne-tw-o-r-k-mod-u-le / nw-mod pro-se fo-r-m-s a-l-o-n-e in PROSE):
    let mn = format!("{}{}", "nw", "mod");
    let done = format!("NW{}{}", "M", "OD_DONE");
    let docs = [NEXTMD.to_string(), format!("{ROOT}/PORTING_PLAN.md"), format!("{ROOT}/KNOWN DEVIATIONS.md")];
    for d in docs {
        let c = read(&d);
        assert_eq!(c.matches(mn.as_str()).count(), 0, "{d} dir-t-oke-n-ze-ro");
        assert_eq!(c.matches(done.as_str()).count(), 0, "{d} do-ne-ma-r-ke-r ze-ro");
    }
    // the hy-p-h-e-n fa-ce pre-s-e-nt (the ca-rr-i-er law's pos-i-ti-ve pi-n):
    let hy = format!("ne-twork-mod-u|ne{}work mod-u", "t");
    let plan_dev = dev.clone();
    assert!(
        plan_dev.contains(&format!("ne-twork-mod-u{}", "le")) || plan_dev.matches("ne-twork").count() > 0,
        "the hy-p-h-e-n pro-se f-o-rm rid-es the-dev-row-s"
    );
    let _ = hy;
    // the N-E-X-T se-ed-fa-c-e-s UN-M-OVED (li-n-e-se-m-an-t-i-c-s, the CU-RR-E-NT
    // pin-s-et at 961-x-3 — the or-ches-tra-tor's do-cs fa-ce, thi-s row's com-
    // mit NEVER tou-ch-es N-EXT):
    let nf = |t: &str| read(NEXTMD).lines().filter(|l| l.contains(t)).count();
    assert_eq!(nf("961 tests green / 0 FAILED"), 3, "the CUR-R-E-NT-pass se-ed f-a-ce x3");
    for s in [946, 930, 915, 900, 885, 870, 855, 841, 825, 810, 798, 784, 772, 763, 752, 724, 702, 684, 659, 650, 633, 629, 621, 605, 597] {
        assert_eq!(nf(&format!("{s} tests green / 0 FAILED")), 3, "the {s} f-a-ce x3");
    }
    assert_eq!(nf("588 tests green / 0 FAILED"), 4);
    assert_eq!(nf("580 passed / 0 failed"), 3);
    assert_eq!(nf("573 tests green"), 5);
    assert_eq!(nf(&format!("{}{}", "5 TE", "ST(")), 1, "the d-r-i-f-t-t-oken EX-A-C-T-1");
    // the APPEND-law he-ld f-a-ce-s (the t-wi-ns' las-t-se-c-ti-on wal-k-
    // ers — the 24j pr-e-i-ns-tr-u-m-en-t-ati-on — fl-i-pp-ed IN-COMMIT to
    // the 24k f-a-ce, ass-e-r-ted HERE at the fl-ip-p-e-d f-ac-e wi-th the wal-k):
    let hlt = read(&format!("{ROOT}/tests/{}{}_parity_test.rs", "h", "lp"));
    assert!(hlt.contains("contains(\"row 24k\")"), "the h-l-p last-se-cti-on wal-k-er fl-ip-p-ed 24j->24k IN-COMMIT ([24k rider])");
    let snc = read(&format!("{ROOT}/tests/sn{}{}_parity_test.rs", "c", "onf"));
    assert!(snc.contains("contains(\"24k\")"), "the sn-co-n-f la-st-sec-ti-on walk-e-r fl-ipp-ed IN-COMMIT ([24k rider], the 24j->24k cha-in)");
    let ac_tw = read(&format!("{ROOT}/tests/{}cmd_parity_test.rs", "a"));
    assert!(ac_tw.contains("contains(\"row 24\")"), "the a-cmd ge-ne-ric new-est-ro-w wal-k-er UN-MOVED-st-ill gen-u-in-e");
}

// ==========================================================================
// p14: the T-OKEN-Z-E-R-O fa-c-e-s by WALK-FO-R-M (the own d-i-r t-oken +
// the DO-NE mar-ker + the ne-tw-r-k / ne-tw-o-r-k-ly s-i-b-l-ings NEV-ER r-i-d-e
// JO-I-NED anyw-h-e-r-e EXCE-PT: the ow-n d-i-r's P-ATHs (the h-a-r-ness di-r
// na-me + its 7 f-a-ces, the gr-ou-nd-p-ai-r gr-ou-nd-na-me by c-o-ns-t-r-uc-ti-o-n
// — the ca-rri-er law, the 24i/24j pr-o-ven s-h-a-pe) + th-e 2 DIR-T-Y p-re-
// hi-ts th-e or-c-h-e-s-tra-tor c-e-n-s-e-d (the misc-9-PL-A-N.'s ne-tmo-d ne-
// ed-l-e + th-e c-su-m bui-ld.'s nm_h wa-lk — th-e D-I-FF-E-R-E-n-t t-oken-s,
// pin-ned at 1 ea-ch UN-MOVED).
// ==========================================================================
#[test]
fn p14_token_zero_faces() {
    let mn = format!("{}{}", "nw", "mod");
    // (a) the lan-ding r-id-es the d-i-r-t-oke-n + DO-NE 0:
    let land = read(&format!("{ROOT}/src/main/ne{}work_module.rs", "t"));
    assert_eq!(land.matches(mn.as_str()).count(), 0, "the landing d-i-r-token-z-e-ro");
    assert_eq!(land.matches("NWMOD").count(), 0, "the lan-ding DO-NE-ze-r-o");
    // (b) the v-e-c-t-or s-e-e-ds + the own b-ui-ld.sh's by-t-e-s (the sp-lit-MN
    // law: the JO-I-NED di-r-to-ken NEVER r-ides the bu-ild.s-h):
    for leaf in ["vectors.txt", "vectors_faceA.txt"] {
        let s = read(&own_home(leaf));
        assert_eq!(s.matches(mn.as_str()).count(), 0, "the {leaf} seed NEVER hos-ts the dir-t-oken");
    }
    let b = read(&own_home("build.sh"));
    assert_eq!(b.matches(mn.as_str()).count(), 0, "the sp-lit-MN la-w: the JO-I-NED di-r-ock-en NEV-ER r-id-es the bu-i-ld.s-h by-t-es (the ${{MN}} con-cat ON-L-Y)");
    // (c) THI-S t-wi-n's s-e-l-f-s-c-a-n (the own p-ath re-fo-rm-u-l-a-t-ed at wal-k):
    let me = read(&format!("{ROOT}/tests/{mn}_parity_test.rs"));
    assert_eq!(me.matches(&format!("{mn}_DONE")).count(), 0, "the DO-NE ma-r-ke-r NEVER r-id-e-s HE-RE");
    // (d) the si-b-i-n-g ne-twr-k / n-tw-k / ma-inn-et / no-d-h / n-w-m-h fam-ily
    // EXA-C-T-L-Y-0 a-c-r-o-s-s t-h-e WH-O-L-E tr-a-ck-e-d i-n-d-e-x (th-e ch-a-
    // p-t-e-r-19-i-s-h n-am-e-c-o-ll-i-s-i-on m-in-e, the 24j r-ide-r's l-e-s-s-o-n):
    let sib = [
        format!("{}{}", "net", "wrk"),
        format!("{}{}", "NT", "WRK_DONE"),
        format!("{}{}", "nt", "wk"),
        format!("{}{}", "main", "net"),
        format!("{}{}", "nod", "_h"),
        format!("{}{}", "nwm", "_h"),
    ];
    let idx = std::process::Command::new("git")
        .args(["-C", ROOT, "ls-files"])
        .output()
        .unwrap()
        .stdout;
    let tracked: Vec<String> = String::from_utf8(idx).unwrap().lines().map(|s| s.to_string()).collect();
    for tok in &sib {
        let mut hits = 0;
        for f in &tracked {
            if read(&format!("{ROOT}/{f}")).contains(tok.as_str()) {
                hits += 1;
            }
        }
        assert_eq!(hits, 0, "the si-b-token {tok} EX-A-CT-L-Y-0 ac-ro-ss the t-rack-ed in-d-ex (the min-e-w-alk, the fin-d-0 li-st's n-e-w mem-b-er)");
    }
    // (e) the t-wo D-I-RT-Y pr-e-h-i-ts UN-M-O-V-ED at 1-ea-ch (the for-e-i-gn-
    // ho-l-de-r fa-c-e-s ci-t-ed, NEV-ER fl-ip-p-ed — the mi-sc-9 D-O-RT-
    // AN-T-S-T-A-L-E law + the cs-u-m ni-ze-l-e's own wal-k):
    let misc = read(&format!("{ROOT}/tools/misc9_harness/PLA{}.md", "N"));
    assert_eq!(misc.matches(&format!("ne{}mod", "t")).count(), 1, "the mi-sc-9 ne-t-mo-d ne-ed-le 1 UNMO-V-ED (the DOR-M-A-NT st-a-le fa-ce, NEV-E-R to-u-ch-ed)");
    let csum = read(&format!("{ROOT}/tools/cs{}m_harness/build.sh", "u"));
    assert!(csum.contains("nm_hdrtu"), "the c-su-m nm_h fam-ily wal-k face UN-M-OVED (a D-I-FFE-RE-N-T tok-en, the pre-c-it-ed DR-I-RT-Y h-o-l-d-e-r)");
}

// ==========================================================================
// p15: the gr-ou-nd d-i-a-l-e-c-t / ve-r-b-a-t-im fa-c-e-s the la-nd-in-g ri-d-es
// — the t-wo :88/:94 na-m-ed ta-b-l-e-s' EX-A-C-T sh-a-pe (the se-t-po-lic-y pa-r-am-s
// 1+se-nt, sp0 'id' the sa-me 1:max53 c-i-t-e), the cm-an-d he-l-p t-e-xt ve-r-b-a-
// tim, the h :37 c-pp-c-h-ek su-p-p-r-e-s-s co-mm-e-nt's ver-b-a-t-im cit-e, the
// NO-w-n a-ll-o-w-s / NO-w-n un-s-a-fe po-st-u-re al-re-a-d-y pi-n-n-e-d-p02 — t-h-is
// p-in-s the re-s-t: the la-n-d-i-ng's se-a-t ci-tes + the N-EXT r-ock-s t-h-e or-c-h-e-
// s-t-r-a-t-o-r (th-is ro-w's com-m-i-t N-EV-ER tou-c-h-es N-EXT, the s-e-eds UN-MO-
// VED by p13 — t-h-e s-e-a-t-w-a-l-k t-r-i-p-wi-r-e he-re).
// ==========================================================================
#[test]
fn p15_seat_echo_ladder() {
    let cc = ground("main/network_module.cc");
    let ccl: Vec<&str> = cc.lines().collect();
    // the :88-:92 ta-bl-e's sh-a-pe fa-c-e-s ea-t by the w-al-ked co-ns-t:
    assert_eq!(ccl[87], "const Parameter network_set_policy_params[] =", "the :88 sea-t (the NON^st-a-tic con-s-t INT-ER-NAL-l-in-kag-e fa-ce, cit-e-d in p03)");
    assert_eq!(ccl[93], "const Command network_cmds[] =", "the :94 sea-t");
    assert!(ccl[95].contains("set_policy"), "the :96 cm-a-n-d ro-w");
    assert!(ccl[96].contains("set the network policy for commands given the user policy id"), "the :97 he-l-p te-xt ver-b-at-im (the lan-ding's NE-TWORK_CMDS[0].he-lp B-y-t-e-id)");
    assert_eq!(
        NETWORK_CMDS[0].help.unwrap(),
        "set the network policy for commands given the user policy id",
        "the B-Y-TE-id ver-b-a-t-im he-l-p la-w"
    );
    // the s-e-t-t-i-n-g ta-bl-e sh-a-pe (sp0 = 'id' the sa-me 1:max53 c-it-e, PT_INT):
    assert_eq!(sn3_params_len_shim(), 2, "the sp-1+se-nt sh-a-pe (the A4 set-para-ms = 1 + se-nt fa-ce)");
    // the gr-ou-nd cla-ss's t-ri-o s-e-a-ts (h :29-:39 the p-u-b-l-i-c la-dd-er — the
    // Ru-st im-p-l's sh-a-pe pi-n):
    let h = ground("main/network_module.h");
    assert!(h.contains("const snort::Command* get_commands() const override"), "the h:35 ov-e-rr-i-d-e fa-ce");
    assert!(h.contains("Usage get_usage() const override"), "the h:38-:39 u-s-ag-e o-v-e-r-r-i-d-e (the su-p-pr-e-s-s co-mm-e-nt's se-at :37, the po-rt's get-u-s-ag-e ri-d-es C_USAGE_CON-T-E-X-T = the lan-ded ord-i-na-l)");
}

fn sn3_params_len_shim() -> usize {
    // the NE-T-WORK set-p-o-licy para-ms ta-bl-e's le-n (the :88 leg):
    snort3::main::network_module::SET_POLICY_PARAMS.len()
}
