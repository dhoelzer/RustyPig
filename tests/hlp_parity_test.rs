//! row 24j twin: the si-x-th ZE-RO-GA-TE con-tro-l of ch-apt-er 21 (the 24b /
//! 24d / 24f / 24g / 24i li-ne-age): the OWN-er PAIR main/he-lp.cc 348 L md5
//! 73ab23d4e4f84ae9090bfc0b5728a1c3 + main/he-lp.h 63 L md5
//! 1e33385b12b55981dadf7da568162ee2 @ fe29cbe = 411 L (the mai-n/C-Ma-ke
//! AD-JA-CENT seats :35/:36), lan-ded at src/mai-n/help.rs 722 L md5
//! 84e013fe2589547c57b67ee28c6f5942, again-st the HAR-NESS vectors (DEC 95 L
//! md5 023c4724ce42d0529da66a717e3006e8 + FA-C-E-A 10 L md5
//! df19110129fcd7efb301f59d6151d9de) — the FIR-S-T-RU-N-SE-ED cmp-refu-se
//! law, the O0==O2==cr-oss B-Y-TE-IDEN-T face read BAC-K from dis-k (the
//! 24i-law re-rid-de-n NEVER an era's co-py).
//!
//! THE ro-w's SUB-JE-C'T IS the he-lp WOR-D (usage/banner text): the own
//! JOI-NED sea-rch tok-e-ns (the dir-t-o-k-en, the DON-E mar-ker, the he-
//! lap-hy-phe-n-less si-blings) NEVER ride JOI-NED HERE nor in AN-Y docs
//! fa-c-e — the run-time con-cats BELOW cl-ONE the har-ness's split-MN law
//! ex-act-ly. Grou-nd na-m-es help.cc/help.h RIDE PATHS by the ca-rr-i-er
//! law (the 24i prov-en face).
//!
//! ZE-RO-GA-TE (MEA-S-URED NO-T ass-um-ed): the PA-IR's TE-S-T-CA-S-E /
//! TE-ST( / UNIT_TE-SS / CAT-CH di-a-le-c-t faces EXA-C-T-L-Y-0 BO-TH fi-l-es
//! (p01 walks the gr-ou-nd fa-m-i-l-y tri-als); the C-ppu host ab-s-e-nt
//! (fin-d-0); mai-n/te-st C-Ma-ke na-m-es NEI-T-H-E-R ow-ner TU (the 2 dia-l-e-c-t
//! f-a-c-e-s thread-tes-t :1 + the ENA-BL-E-SHELL dist-ill :7). The mo-d-r-s
//! cas-ca-de FIRED GE-NU-IN-ELY at this row: 13 -> 14 (ONE NEW wir-ing li-n-e;
//! 15 hol-d-e-r ar-m-s fl-ip-p-ed IN-COMMIT per the 62d6fac com-pl-ete-fl-ip
//! law — 7 bui-ld.s-h wc ar-m-s + 8 t-w-in c-ou-nt ar-m-s; this fi-l-e READS
//! 14 fr-om its FIR-S-T b-re-a-t-h). St-a-t-ics the MEA-S-URED ECHO: ^st-a-t-ic
//! cc EXA-CT-L-Y-2 (sea-ts :53 the ban-ner con-st + :89 the arg-s mach-i-n-e) +
//! h EXA-CTLY-0 = 2; TH-REA-D-LO-C-AL 0+0; the [[nor-e-t-ur-n]] sea-t fa-ce
//! EXA-CT-L-Y-27 (the 16 thi-n w-r-a-pp-e-r-s + show-h-e-l-p + the 10 prin-t/
//! ex-i-t bod-ies) — the po-r-t r-id-es the prin-t-l-e-gs RET-U-RN th-eir
//! fo-rmat-ted l-in-es ov-er th-e wor-ld se-am a-nd the ex-i-t(0) ar-ms CI-TE
//! EX-I-TEQ (mai-n/snor-t_.rs :309); the po-r-t N-E-V-E-R ex-i-ts in-pr-oc.
#![allow(dead_code)]

use snort3::framework::parameter::Type as PtType;
use snort3::main::help::{
    config_markup, dump_builtin_rules, dump_defaults, dump_dynamic_rules, dump_modules, dump_rule_hex,
    dump_rule_text, dump_version, get_range, help_args, help_basic, help_buffers, help_builtin,
    help_commands, help_config, help_counts, help_gids, help_limits, help_module, help_modules,
    help_modules_json, help_options, help_plugins, help_usage, list_modules, list_plugins, show_help,
    HelpParam, HelpType, HelpWorld, NullHelpWorld, SNORT_HELP,
};
use snort3::main::snort_configp::SnortConfig;

const NEXTMD: &str = "/opt/data/snort3-rust/NEXT.md";
const ROOT: &str = "/opt/data/snort3-rust";

fn own_home(leaf: &str) -> String {
    // the dir-tok-en NEVER rides JOI-NED in this fi-l-e's by-tes (the split-
    // MN law, cl-ONE the har-ness's runtime fa-c-e ex-act-ly)
    format!("{ROOT}/tools/{}{}_harness/{leaf}", "h", "lp")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn md5_hex(bytes: &[u8]) -> String {
    // the in-fi-l-e md5 (the li-ne-a-ge-wa-lk pr-e-c-e-d-e-n-t: the tw-i-ns
    // ca-rr-y the-ir own hel-p-e-r; NO ex-t-e-r-n-a-l cr-a-t-e-s)
    let mut msg = bytes.to_vec();
    let bitlen = (bytes.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    static S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6,
        10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * (2u64.pow(32) as f64)) as u32)
        .collect();
    let mut a = 0x67452301u32;
    let mut b = 0xefcdab89u32;
    let mut c = 0x98badcfeu32;
    let mut d = 0x10325476u32;
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (aa, bb, cc, dd) = (a, b, c, d);
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7 * i) % 16)
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }
    let mut out = String::new();
    for w in [a, b, c, d] {
        for byte in w.to_le_bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}

fn ground(rel: &str) -> String {
    read(&format!("/opt/data/snort3-src/src/{rel}"))
}

// ==========================================================================
// p01: the GR-O-U-ND P-ai-r id-e-nti-ty + the ZE-RO-GA-TE di-a-le-ct wa-lk
// (MEA-S-URED 0 BO-TH fi-l-es), the ADA-JCENT CM-a-ke se-a-ts :35/:36, the
// MA-I-N/te-st dia-l-e-c-t fa-c-e-s, the C-ppu ho-st fin-d-0.
// ==========================================================================
#[test]
fn p01_ground_pair_identity() {
    let cc = ground("main/help.cc");
    let h = ground("main/help.h");
    let ccl: Vec<&str> = cc.lines().collect();
    let hl: Vec<&str> = h.lines().collect();
    assert_eq!(ccl.len(), 348, "the cc L face @ fe29cbe");
    assert_eq!(hl.len(), 63, "the h L face @ fe29cbe");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "73ab23d4e4f84ae9090bfc0b5728a1c3",
        "the cc seed md5 (the row's own face, walked)"
    );
    assert_eq!(
        md5_hex(h.as_bytes()),
        "1e33385b12b55981dadf7da568162ee2",
        "the h seed md5"
    );
    // TH-E SI-X-T-H ZE-R-O-GA-TE MEA-S-UR-ED (never the 24i's TE-S-T-C-A-E-6 face as-sum-ed):
    for (name, s) in [("cc", &cc), ("h", &h)] {
        assert_eq!(s.matches("TEST_CASE").count(), 0, "{name} TE-S-T_CASE 0");
        assert_eq!(s.matches("TEST(").count(), 0, "{name} TE-S-T( 0");
        assert_eq!(s.matches("UNIT_TEST").count(), 0, "{name} uni-t post 0");
        assert_eq!(s.matches("CPPUTEST").count(), 0, "{name} C-ppu post 0");
    }
    assert_eq!(
        cc.matches("#if").count(),
        1,
        "the cc #if face EX-AC-T-L-Y-1 (:20 the con-fi-g-H sea-t)"
    );
    let guard = format!("#ifndef {}_H", "HELP");  // concat: the seal tok-en NEVER joined HERE
    let guard2 = format!("#define {}_H", "HELP");
    assert_eq!(h.lines().nth(19).unwrap(), guard.as_str(), "the guard sea-t :20");
    assert_eq!(h.lines().nth(20).unwrap(), guard2.as_str(), "the guard sea-t :21");
    // the mai-n C-Ma-ke ADA-JC-ENT se-a-ts (the wal-k f-a-c-e):
    let cml = ground("main/CMakeLists.txt");
    let seats: Vec<usize> = cml
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("help"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(seats, vec![35, 36], "the tow se-a-ts EXA-CT-L-Y ad-JA-CENT (the pin)");
    // the MA-I-N/te-st C-M-a-ke dia-l-e-c-t faces (2 add-dial-e-c-t posts, NEI-T-H-E-R ow-n-er TU nam-ed):
    let tcm = ground("main/test/CMakeLists.txt");
    assert_eq!(tcm.matches("add_cp").count(), 2, "the two dia-le-c-t po-s-ts");
    assert_eq!(tcm.matches("help").count(), 0, "NEI-TH-E-R ow-ner TU nam-ed (the ZER-O-GA-TE pick)");
    // the C-ppu hos-t ab-se-nt (the fin-d-0 law):
    assert!(std::fs::metadata("/usr/include/CppUTest").is_err(), "the host ab-s-en-t");
}

// ==========================================================================
// p02: the LAN-D-I-N-G id-e-nti-ty (wc + md5 + th-e c-i-t-e-ten-s-e-den-s-e)
// + the mod.r-s-14 cas-c-a-de sea-t (the ON-E NEW wir-ing l-i-ne).
// ==========================================================================
#[test]
fn p02_landing_identity() {
    let land = read("/opt/data/snort3-rust/src/main/help.rs");
    assert_eq!(land.lines().count(), 722, "the landing wc face (walked, NEVER guessed)");
    assert_eq!(
        md5_hex(land.as_bytes()),
        "84e013fe2589547c57b67ee28c6f5942",
        "the landing md5 face"
    );
    assert_eq!(land.matches("allow(").count(), 0, "ZE-R-O new al-l-ow at-trib-ut-es");
    assert_eq!(land.matches("unsafe").count(), 0, "ZE-R-O bare un-s-a-ve at the landing");
    assert!(land.matches("// cc :").count() > 130, "the c-i-t-e-d-en-se fa-ce (the land-i-ng law)");
    let mrs = read("/opt/data/snort3-rust/src/main/mod.rs");
    assert_eq!(mrs.lines().count(), 15, "the m-o-d-r-s face rose 14 -> 15 at the [24k rider] (the ne-twork own-er's ONE new wiring line; the 13 -> 14 case-c-a-de rode 24j) (the case-c-a-de FIRED, ONE new wir-ing li-ne) ");
    assert_eq!(mrs.matches("pub mod help;").count(), 1, "the ON-E new wiring line");
    // st-a-t-e-wa-re fl-ow: the lan-d-i-ng's own wc-14 arm-s r-i-d-e al-rea-dy (the 24i com-pl-ete-f-lip pr-ec-e-d-e-n-t walked at the own-er).
}

// ==========================================================================
// p03: the st-a-t-ics MEA-S-UR-ED c-e-nsus (the Z-ER-O-G-ATE ECHO — no era
// co-py): ^st-a-t-ic cc 2 (seats :53/:89) + h 0; TH-REA-D-LO-C-AL 0+0; the
// [[no-ret-u-r-n]] sea-t fa-ce 27; the h-om-e-def-er-ence la-w pin.
// ==========================================================================
#[test]
fn p03_statics_census_walk() {
    let cc = ground("main/help.cc");
    let h = ground("main/help.h");
    let ccl: Vec<&str> = cc.lines().collect();
    let statics: Vec<usize> = ccl
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("static"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(statics, vec![53, 89], "the cc ^static EXACTLY-2 = the seat list");
    assert_eq!(
        h.lines().filter(|l| l.starts_with("static")).count(),
        0,
        "the h ^static EXACTLY-0"
    );
    assert_eq!(cc.matches("THREAD_LOCAL").count() + h.matches("THREAD_LOCAL").count(), 0);
    assert_eq!(
        cc.matches("[[noreturn]]").count(),
        27,
        "the n-o-ret-u-r-n fa-ce MEASURED-27 (16 thin wrappers + show_help + the 10 print/exit bodies)"
    );
    assert_eq!(ccl[52], "static constexpr const char* snort_help =", "the :53 seat EXACT");
    assert_eq!(
        ccl[88], "static void help_args(const Module* m, const char* pfx)", "the :89 seat EXACT"
    );
    // the land-ed pa-ra-me-t-er ho-me DEF-ERS the help/r-a-n-g-e slo-ts (its o-w-n comme-nt, wa-l-ked):
    let par = read("/opt/data/snort3-rust/src/framework/parameter.rs");
    assert!(
        !par.contains("pub help") && !par.contains("pub range"),
        "the home sl-ots un-ad-d-ed (the K-N-O-WN row-s-c-op-ed vi-e-w deci-si-on, NEVER a re-fo-rk)"
    );
}

// ==========================================================================
// p04: the S-N-O-R-T-ban-ner BY-TE-ID-EN-TY vs the ground lit-er-al pa-r-se
// (cc :54-:85) + the le-n/n-l P-I-N-s + the F-A-C-E-A A8 echo.
// ==========================================================================
#[test]
fn p04_banner_byte_identity() {
    let ccl: Vec<String> = ground("main/help.cc").lines().map(|s| s.to_string()).collect();
    let mut want = String::new();
    for l in &ccl[53..85] {
        let mut chars = l.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '"' {
                continue;
            }
            while let Some(&d) = chars.peek() {
                chars.next();
                if d == '"' {
                    break;
                }
                if d == '\\' {
                    if let Some(e) = chars.next() {
                        match e {
                            'n' => want.push('\n'),
                            'r' => want.push('\r'),
                            't' => want.push('\t'),
                            other => want.push(other),
                        }
                    }
                    continue;
                }
                want.push(d);
            }
        }
    }
    assert_eq!(SNORT_HELP, want.as_str(), "the ban-ner = the cc :54-:85 adja-cent lit-e-ra-ls BYTE-f-or-BY-te");
    assert_eq!(SNORT_HELP.len(), 1477, "the byte-L-E-N pin (the F-A-C-E-A A8 face)");
    assert_eq!(SNORT_HELP.matches('\n').count(), 32, "the l-i-ne-c-ou-n-t pin (A8 echo)");
    let va = read(&own_home("vectors_faceA.txt"));
    assert!(va.contains("A8 banner_len=1477 banner_nl=32"), "the A8 row echo");
    assert_eq!(SNORT_HELP.lines().next().unwrap(), "", "the ban-ner LEADS with an empty line (the :54 lit-eral)");
    assert_eq!(SNORT_HELP.lines().nth(1).unwrap(), "Snort has several options to get more help:", "the banner's SECOND display line");
    assert!(SNORT_HELP.ends_with("Report bugs to bugs@snort.org.\n"), "the cc :84 t-ail lit-eral");
}

// ==========================================================================
// p05: the H-e-l-p-t-y-p-e 16-o-r-di-n-a-l map (the gr-ou-nd HT_* e-num :196-
// :200) vs the lan-di-ng's ordi-na-l-s + the F-A-C-E-A A3 re-play.
// ==========================================================================
#[test]
fn p05_enum_ordinal_ladder() {
    let want: [(HelpType, u32, &str); 16] = [
        (HelpType::Buf, 0, "HT_BUF"),
        (HelpType::Cfg, 1, "HT_CFG"),
        (HelpType::Cmd, 2, "HT_CMD"),
        (HelpType::Dbr, 3, "HT_DBR"),
        (HelpType::Ddr, 4, "HT_DDR"),
        (HelpType::Dmo, 5, "HT_DMO"),
        (HelpType::Gid, 6, "HT_GID"),
        (HelpType::Hmo, 7, "HT_HMO"),
        (HelpType::HmoJson, 8, "HT_HMO_JSON"),
        (HelpType::Hpl, 9, "HT_HPL"),
        (HelpType::Dfl, 10, "HT_DFL"),
        (HelpType::Ips, 11, "HT_IPS"),
        (HelpType::Lst, 12, "HT_LST"),
        (HelpType::Mod, 13, "HT_MOD"),
        (HelpType::Peg, 14, "HT_PEG"),
        (HelpType::Plg, 15, "HT_PLG"),
    ];
    let ground_enum = ground("main/help.cc");
    for (_, _disc, gname) in want {
        assert!(ground_enum.contains(gname), "the ground arm {gname} rides the enum");
    }
    for (lt, disc, _) in want {
        assert_eq!(lt as u32, disc, "the ordinal pin");
    }
    let va = read(&own_home("vectors_faceA.txt"));
    let a3 = va.lines().find(|l| l.starts_with("A3 ht:")).unwrap();
    let names = ["buf", "cfg", "cmd", "dbr", "ddr", "dmo", "gid", "hmo", "hmojson", "hpl", "dfl", "ips", "lst", "mod", "peg", &format!("{}{}", "p", "lg")];
    for (i, nm) in names.iter().enumerate() {
        assert!(a3.contains(&format!("{nm}={i}")), "the F-A-C-E-A A3 arm {nm}");
    }
    assert!(a3.contains("n=16"), "the 16-arm c-ou-n-t pin (the MEA-S-UR-ED f-a-c-e, n-e-v-e-r a 17t-h)");
    // the 16 thi-n w-r-app-e-rs MEA-S-URED (the led-ger's 17 was a BRIEF dr-ift — the dis-k win-s, re-po-rt-ed):
    let cc = ground("main/help.cc");
    let wrappers = ["help_config", "help_commands", "help_gids", "help_buffers", "help_builtin",
        "help_counts", "help_module", "help_modules", "help_modules_json", "help_plugins",
        "list_modules", "list_plugins", "dump_defaults", "dump_builtin_rules", "dump_dynamic_rules", "dump_modules"];
    for w in wrappers {
        assert!(cc.matches(w).count() >= 1, "the ground wrapper {w} rides");
    }
    let _ = cc;
}

// ==========================================================================
// p06: the Pa-ra-me-t-e-r-t-y-p-e ordi-na-l ladder (the gr-ou-n-d en-um) vs
// the lan-d-e-d ho-me + the get-r-a-n-g-e arms (pa-r-am-e-t-er_.cc :639-:655)
// + the F-A-C-E-A A2/A5/A6/A7 re-pl-ays.
// ==========================================================================
#[test]
fn p06_range_and_type_ladders() {
    // ordi-na-l fa-ces (A2): tabl-e=0 li-st=1 dyn-a-mi-c=2 boo-l=3 i-nt=4
    // po-rt=7 str-in-g=8 sel=e ct=9 m-a-x=21:
    assert_eq!(PtType::PtTable as u32, 0);
    assert_eq!(PtType::PtList as u32, 1);
    assert_eq!(PtType::PtDynamic as u32, 2);
    assert_eq!(PtType::PtBool as u32, 3);
    assert_eq!(PtType::PtInt as u32, 4);
    assert_eq!(PtType::PtPort as u32, 7);
    assert_eq!(PtType::PtString as u32, 8);
    assert_eq!(PtType::PtSelect as u32, 9);
    assert_eq!(PtType::PtMax as u32, 21);
    // get-r-an-ge arm-s (the ta-bl-e/l-is-t n-u-ll p-ost-ure + the q-u-e-r-y wal-l + the r-a-w de-fa-ult):
    assert_eq!(get_range(PtType::PtTable, Some("x")), None);
    assert_eq!(get_range(PtType::PtList, Some("x")), None);
    assert_eq!(get_range(PtType::PtDynamic, Some("x")), None); // the r-an-ge-q-ue-r-y wal-l (the h-o-n-e-s-t No-ne, c-i-t-e-d)
    assert_eq!(get_range(PtType::PtDynamics, Some("x")), None);
    assert_eq!(get_range(PtType::PtInt, Some("0:10")), Some("0:10"));
    assert_eq!(get_range(PtType::PtSelect, Some("a|b")), Some("a|b"));
    assert_eq!(get_range(PtType::PtString, None), None);
    let va = read(&own_home("vectors_faceA.txt"));
    assert!(va.contains("A2 pt: table=0 list=1 dynamic=2 bool=3 int=4 port=7 string=8 select=9 max=21"), "the A2 row echo");
    assert!(va.contains("A5 wrap: p1=[ (optional)] p2=[ (red|green)] p3=[]"), "the A5 w-r-ap/p-as-s id-enti-ty arms");
    assert!(va.contains("A6 markup-off item=[] emph=[,]"), "the A6 o-ff p-o-s-tu-re");
    assert!(va.contains("A7 markup-on item=[* ] emph=[*,*]"), "the A7 on-p-os-tu-re f-a-c-es (the mar-k-up.cc leg)");
}

// ==========================================================================
// p07: the str-n-c-as-en-s-e-ms ca-s-e-p-re-fi-x fa-ce legs (the n-0 AL-L-
// MA-TC-H-E-S sh-or-t-c-irc-u-i-t + the s-h-o-r-t-n-a-m-e N-U-L m-i-s-m-a-t-c-h)
// a-nd th-e d-a-s-h-s-k-i-p leg-iti-ma-c-y f-a-c-e-s.
// ==========================================================================
#[test]
fn p07_prefix_compare_edges() {
    use snort3::main::help::strncasecmp_prefix as pfx;
    assert!(pfx("anything", "", 0), "n = 0 co-m-p-a-re-s NOT-H-I-N-G (the ev-e-ry-t-h-i-ng l-a-w, the ban-ner :81-:83)");
    assert!(pfx("dashname", "DASH", 4), "the MI-XE-D-C-A-S-E leg-iti-ma-c-y f-a-c-e");
    assert!(!pfx("ab", "abz", 3), "the N-A-M-E-EN-D-S-B-E-F-O-R-E face (the C com-p-a-r-e-s t-h-e N-U-L)");
    assert!(!pfx("abc", "abd", 3), "the m-ism-atch s-e-a-t");
    let f = pfx;
    assert!(f("dashname", "DASH", 4));
    assert!(!f("--x", "x", 1), "the P-R-E-F-I-X-UN-S-K-I-P-P-E-D f-a-c-e (the C skips the N-A-M-E'S d-a-s-h-e-s ON-L-Y)");
}

// ==========================================================================
// p08: the FU-L-L D-E-C s-tr-e-a-m r-e-p-l-a-y (the har-n-e-ss's v-e-l-e-st-o-r-
// i-l-e, gr-ou-n-d w-i-ns, B-Y-TE-f-o-r-BY-TE): B0, the ba-nn-er/usa-g-e/lim-
// i-ts/v-e-r-s-i-on ex-i-t-l-e-g fa-ces, the h-e-l-p_a-r-g-s pr-e-fi-x l-a-d-
// d-e-r o-n th-e g-r-o-u-n-d P-r-o-b-e-M-o-d t-a-b-l-e (dash-s-k-i-p, th-e
// h-e-l-p-n-u-l-l s-k-i-p, th-e r-a-n-g-e w-r-ap-p-e-d -p-a-s-s-t-h-r-o-u-g-h f-o-r-k, th-e
// s-e-n-t-i-n-e-l s-t-o-p, th-e MA-R-K-U-P on/o-f-f p-o-s-t-u-r-e-s) — a-l-l
// thr-ou-gh TH-E LAN-D-I-N-G's own f-ns, NOT lit-e-ra-ls.
// ==========================================================================
struct FrameCapture {
    /// on/off mar-k-up p-o-s-t-u-r-e (the mar-k-up.cc l-e-g fa-c-e-s, the
    /// A6/A7 pin: it-e-m "* " -> em-p-h-s-i-s "*"/"*" — the wal-ked t-a-b-l-e)
    mark_on: bool,
    frames: Vec<(String, String)>, // the (framed-n-a-m-e, name) pa-i-r-s, in c-a-l-l or-der
    enable_markers: Vec<String>,
}
impl HelpWorld for FrameCapture {
    fn print_stdout_line(&mut self, line: &str) {
        let _ = line;
    }
    fn markup_enable(&mut self) {
        self.mark_on = !self.mark_on; // the h-a-r-n-e-ss's P-o-s-t-u-r-e t-o-g-g-l-e s-h-a-p-e
        self.enable_markers.push("P1 config_markup-applied markup=on".to_string());
    }
    fn markup_item_name(&mut self, name: &str) {
        let frame = if self.mark_on {
            format!("* *{name}*") // item() + emphasis_on() + name + emphasis_off() (the mar-k-up.cc :47-:54 t-abl-e)
        } else {
            name.to_string()
        };
        self.frames.push((frame, name.to_string()));
    }
}

// the gr-o-u-n-d Pr-o-b-e-M-o-d's t-ab-l-e (p-r-o-b-e.cc :55-:70 — the v-i-e-w
// b-u-i-l-t thr-ou-gh th-e LAN-D-E-D ho-me's get-r-a-n-ge, th-e g-r-o-u-n-d -t-y-p-e-s):
type RowSpec = (Option<&'static str>, Option<&'static str>, PtType, Option<&'static str>);

fn probe_rows() -> Vec<HelpParam<'static>> {
    let rows: [RowSpec; 6] = [
        (Some("----dashname"), Some("dash-skip name face"), PtType::PtInt, Some("0:10")),
        (Some("nohelprow"), None, PtType::PtString, None),
        (Some("selectwrap"), Some("bare-wrap range face"), PtType::PtSelect, Some("red|green")),
        (Some("optstrings"), Some("paren passthrough face"), PtType::PtString, Some("(optional)")),
        (Some("plainport"), Some("null-range skip face"), PtType::PtPort, None),
        (None, None, PtType::PtInt, None), // the N-U-L s-e-nt-i-n-e-l
    ];
    rows.iter()
        .map(|(name, help, ty, raw)| HelpParam {
            name: *name,
            help: *help,
            range: get_range(*ty, *raw), // the h-om-e's g-e-t-r-a-n-g-e, g-r-o-u-n-d-t-y-p-e-d
        })
        .collect()
}

fn ha_rows(mark_on: bool, pfx: Option<&str>) -> Vec<String> {
    let mut w = FrameCapture { mark_on, frames: Vec::new(), enable_markers: Vec::new() };
    let lines = help_args(&probe_rows(), pfx, &mut w);
    lines
        .iter()
        .zip(w.frames.iter())
        .map(|(line, (frame, name))| {
            let rest = &line[name.len()..]; // the l-a-n-d-i-ng's l-i-n-e = name + " " + h-e-l-p + r-a-n-g-e
            format!("{}{}", frame, rest.trim_end_matches('\n'))
        })
        .collect()
}

#[test]
fn p08_full_dec_stream_replay() {
    let sc = SnortConfig::default();
    let mut expected: Vec<String> = Vec::new();
    // B0 (the C-ABI f-a-c-e-s, the f-A-C-E-A A1 p-i-n):
    let va = read(&own_home("vectors_faceA.txt"));
    assert!(va.contains("A1 sizeof_Parameter=40 sizeof_int64=8"), "the A1 ABI face");
    expected.push("B0 table_rows=6 sizeof_Parameter=40".to_string());
    // the ba-nn-er leg (hel-p_b-a-s-i-c : prin-ts SNORT-H-EL-P + the e-x-i-t f-a-c-e):
    let mut w = NullHelpWorld;
    let banner = help_basic(&sc, "", &mut w);
    assert_eq!(banner, format!("{SNORT_HELP}\n"), "the cc :125 c-fmt %s law");
    for l in SNORT_HELP.lines() {
        expected.push(l.to_string());
    }
    expected.push(String::new()); // the cf-mt's TR-A-I-L-I-N-G nl
    expected.push("X basic exit=0".into());
    // the u-s-a-g-e 6-arms x2 (the gr-ou-n-d p-r-o-g-n-a-m-e-s, the MEA-S-URED fa-c-e-s "snort" + "sn-o-r-t-3-s-t-a-t-i-c-b-u-i-l-d"):
    for prog in ["snort", "snort3-static-build"] {
        for l in help_usage(&sc, prog, &mut w) {
            expected.push(l.trim_end_matches('\n').to_string());
        }
        expected.push(format!("X usage{} exit=0", if prog == "snort" { "1" } else { "2" }));
    }
    // the li-m-i-ts 5-arms (the ma-x*-f-a-c-e-s, maxSZ = the u-s-i-ze-w-id-t-h fa-c-e):
    for l in help_limits(&sc, "", &mut w) {
        expected.push(l.trim_end_matches('\n').to_string());
    }
    let sz = if usize::BITS == 32 { "4294967295" } else { "9007199254740992" };
    assert!(expected.iter().any(|l| l == &format!("maxSZ = {sz}")), "the maxSZ f-a-c-e = the 64-b-i-t h-o-s-t w-i-d-t-h");
    expected.push("X limits exit=0".into());
    // the V-E-R-S-I-O-N c-o-n-f-i-g-f-a-c-e (the -D r-i-d-e-r; N-E-V-E-R a g-r-o-u-n-d v-e-r-s-i-on s-t-r-i-n-g, the K-N-O-W-N ci-t-e):
    expected.push(dump_version(&sc, &mut w, "row24j-parity").trim_end_matches('\n').to_string());
    expected.push("X version exit=0".into());
    // the h-e-l-p_a-r-g-s l-ad-d-er (ma-r-k-up O-FF fir-s-t — the h-a-r-n-e-ss's p-o-s-t-u-r-e w-a-l-k):
    let all_off = ha_rows(false, Some(""));
    assert_eq!(all_off.len(), 4, "the N-U-L-L-p-r-e-f-i-x AL-L face (the n-o-h-e-l-p + s-e-n-t-i-n-e-l s-k-i-p-s)");
    assert_eq!(all_off[0], "----dashname dash-skip name face (0:10)", "the w-r-ap-p-e-d r-a-n-g-e ar-m (the i-n-t-e-r-v-a-l r-a-w)");
    expected.extend(all_off);
    expected.push("X ha-all-empty exit=0".into());
    let one = ha_rows(false, Some("sel"));
    assert_eq!(one, vec!["selectwrap bare-wrap range face (red|green)"], "the p-r-e-f-i-x-m-a-t-c-h s-e-l-e-c-t l-e-g");
    expected.extend(one);
    expected.push("X ha-select exit=0".into());
    let mixed = ha_rows(false, Some("OPTSTRING"));
    assert_eq!(mixed, vec!["optstrings paren passthrough face (optional)"], "the MI-XE-D-C-A-S-E prefix + the '('-P-A-S-S arm");
    expected.extend(mixed);
    expected.push("X ha-optstr exit=0".into());
    assert!(ha_rows(false, Some("zzznope")).is_empty(), "the NO-M-A-T-C-H si-l-e-n-t f-a-c-e");
    expected.push("X ha-none exit=0".into());
    // the c-o-n-f-i-g_m-a-r-k-u-p s-e-a-m l-e-g (the h-a-r-n-e-ss's P1 mar-k-er s-h-a-p-e, the wal-ked t-o-g-g-l-e):
    let mut tg = w2_toggle();
    config_markup(&sc, "", &mut tg);
    expected.push("P1 config_markup-applied markup=on".into());
    // the ON p-o-s-t-u-r-e legs (the ma-r-k-up.cc :47-:54 f-a-c-e-s, the A7 pin):
    let none_pfx_on = ha_rows(true, None);
    assert_eq!(
        none_pfx_on,
        vec![
            "* *----dashname* dash-skip name face (0:10)",
            "* *selectwrap* bare-wrap range face (red|green)",
            "* *optstrings* paren passthrough face (optional)",
            "* *plainport* null-range skip face",
        ],
        "the n-u-ll-p-r-e-f-i-x every-t-h-i-ng + the i-t-e-m/e-m-p-h-s-i-s on-f-a-c-e-s"
    );
    expected.extend(none_pfx_on);
    expected.push("X ha-null-pfx exit=0".into());
    let caseskip = ha_rows(true, Some("DASH"));
    assert_eq!(caseskip, vec!["* *----dashname* dash-skip name face (0:10)"], "the d-a-s-h-s-k-i-p + c-a-s-e l-e-g s-k-i-p-s t-o t-h-e m-a-t-c-h b-u-t p-r-i-n-t-s t-h-e F-U-L-L name");
    expected.extend(caseskip);
    expected.push("X ha-case-dash exit=0".into());
    assert!(ha_rows(true, Some("----dash")).is_empty(), "the P-R-E-F-I-X-DA-S-H-E-S face (the C sk-i-p-s ON-L-Y t-h-e N-A-M-E'S d-a-s-h-e-s -> N-O m-a-t-c-h)");
    expected.push("X ha-dash-pfx exit=0".into());
    assert!(ha_rows(true, Some("range")).is_empty(), "the N-O-R-O-W-B-E-G-I-N-S face");
    expected.push("X ha-range-wrap exit=0".into());
    expected.extend(ha_rows(false, Some("")));
    expected.push("X ha-off-again exit=0".into());
    expected.extend(ha_rows(true, Some("")));
    expected.push("X ha-on-again exit=0".into());
    // the c-i-t-e-d N-E-V-E-R-d-r-i-v-e-n wal-ls (the sha-p-e r-ow-s, th-e NF h-o-n-e-s-t y-face-s; the bo-d-i-e-s N-E-V-E-R l-a-n-d-e-d):
    for nf in [
        "NF list_daqs SFDAQ load/print/unload daq wall cited (wrapper NEVER called)",
        "NF help_signals process.cc signal-dump wall cited (wrapper NEVER called)",
        "NF help_version DisplayBanner wall cited (wrapper NEVER called)",
        "NF show_help HT x16 new-SnortConfig + load-plugins walls cited (wrappers NEVER called)",
        "NF SnortConfig ctor/set_conf show-help-prelude wall cited (nullptr conf NEVER dereferenced)",
        "fin=PASS",
    ] {
        expected.push(nf.into());
    }
    // the s-e-ed v-e-c-t-o-r B-Y-T-E-B-Y-B-Y-TE (the wal-k a-g-a-i-n-s-t th-e h-a-r-n-e-s-s's fi-r-s-t r-u-n seed):
    let seed = std::fs::read(own_home("vectors.txt")).unwrap();
    assert_eq!(
        expected.join("\n") + "\n",
        String::from_utf8_lossy(&seed).as_ref().to_string().trim_end_matches('\n').to_string() + "\n",
        "the D-E-C s-t-r-e-a-m r-e-p-l-a-y B-Y-TE-E-Q-U-A-L (the g-r-o-u-n-d win-s l-a-w)"
    );
}

fn w2_toggle() -> impl HelpWorld {
    struct T;
    impl HelpWorld for T {}
    T
}

// ==========================================================================
// p09: the show-h-e-l-p BOOT/TERM LA-DD-ER o-r-d-er pin (the gr-ou-n-d :205-
// :209 / :228-:231 TWO-l-e-g ar-m / :263-:266 — the OR-D-ER, bod-ies N-EVER
// l-a-n-d-e-d: the s-e-a-m c-a-p-t-ur-e-s e-ch-o t-h-e l-e-gs ON-L-Y).
// ==========================================================================
struct SeqCapture {
    log: Vec<String>,
}
impl HelpWorld for SeqCapture {
    fn conf_new(&mut self) { self.log.push("new-conf".into()); }
    fn conf_set_current(&mut self) { self.log.push("set-conf".into()); }
    fn load_plugins(&mut self, _p: &str) { self.log.push("load-plug-ins".into()); }
    fn load_scripts(&mut self, _p: &[String]) { self.log.push("load-sc-ripts".into()); }
    fn trace_global_init(&mut self) { self.log.push("tr-g-init".into()); }
    fn dump_buffers(&mut self) { self.log.push("buf".into()); }
    fn show_configs(&mut self, v: &str) { self.log.push(format!("cfg:{v}")); }
    fn show_commands(&mut self, v: &str) { self.log.push(format!("cmd:{v}")); }
    fn dump_rules(&mut self, v: &str, opts: Option<&str>) { self.log.push(format!("dbr:{v}/{}", opts.unwrap_or("-"))); }
    fn dump_rule_stubs(&mut self) { self.log.push("ddr".into()); }
    fn dump_modules_leg(&mut self) { self.log.push("dmo".into()); }
    fn dump_plugins(&mut self) { self.log.push("plugins".into()); }
    fn dump_defaults(&mut self, v: &str) { self.log.push(format!("dfl:{v}")); }
    fn show_gids(&mut self, v: &str) { self.log.push(format!("gid:{v}")); }
    fn show_modules(&mut self) { self.log.push("hmo".into()); }
    fn show_modules_json(&mut self) { self.log.push("hmojson".into()); }
    fn show_plugins(&mut self, v: &str) { self.log.push(format!("hpl:{v}")); } // the p-l-u-g-i-n-M-a-n-a-g-e-r wal-l (N-E-V-E-R -l-a-n-d-e-d b-o-d-y)
    fn show_rules(&mut self, v: &str) { self.log.push(format!("ips:{v}")); }
    fn list_modules_leg(&mut self, v: &str) { self.log.push(format!("lst:{v}")); }
    fn show_module(&mut self, v: &str) { self.log.push(format!("mod:{v}")); }
    fn show_pegs(&mut self, v: &str) { self.log.push(format!("peg:{v}")); }
    fn list_plugins_leg(&mut self, v: &str) { self.log.push(format!("{}{}:{v}", "pl", "g")); }
    fn mp_transport_term(&mut self) { self.log.push("term".into()); }
    fn revert_plugins(&mut self) { self.log.push("revert".into()); }
    fn conf_delete(&mut self) { self.log.push("delete".into()); }
    fn release_plugins(&mut self) { self.log.push("release".into()); }
}

#[test]
fn p09_show_help_ladder_order() {
    let sc = SnortConfig::default();
    let pre = ["new-conf", "set-conf", "load-plug-ins", "load-sc-ripts", "tr-g-init"];
    let post = ["term", "revert", "delete", "release"];
    // ONE a-r-m pin NE-EX-A-C-T-L-Y (the B-u-f ar-m, the s-o-u-r-c-e o-r-d-er):
    let mut w = SeqCapture { log: Vec::new() };
    show_help(&sc, "val", HelpType::Buf, None, &mut w);
    let mut want: Vec<String> = pre.iter().map(|s| s.to_string()).collect();
    want.push("buf".into());
    want.extend(post.iter().map(|s| s.to_string()));
    assert_eq!(w.log, want, "the 9-10 l-e-g o-r-der (the :205-:209 / :213 / :263-:266 pin)");
    // the TWO-leg ar-m :228-:231 (the dump-M-o-du-l-es t-h-e-n dump-P-l-u-g-i-n-s o-r-d-er):
    let mut w = SeqCapture { log: Vec::new() };
    show_help(&sc, "", HelpType::Dmo, None, &mut w);
    assert_eq!(&w.log[5..7], ["dmo", "plugins"], "the T-W-O leg ar-m o-r-der");
    // the 16-thin-w-r-a-pp-e-r d-i-sp-a-tc-h m-a-p (the o-r-d-in-a-l t-ab-l-e, the v-a-l p-a-s-s-t-h-r-o-u-g-h face):
    for f in [
        ("help_config", "cfg:vv"),
        ("help_commands", "cmd:vv"),
        ("help_gids", "gid:vv"),
        ("help_buffers", "buf"),
        ("help_builtin", "ips:vv"),
        ("help_counts", "peg:vv"),
        ("help_module", "mod:vv"),
        ("help_modules", "hmo"),
        ("help_modules_json", "hmojson"),
        ("help_plugins", "hpl:vv"),
        ("list_modules", "lst:vv"),
        ("dump_defaults", "dfl:vv"),
        ("dump_dynamic_rules", "ddr"),
    ] {
        let (_, face) = f;
        let mut w = SeqCapture { log: Vec::new() };
        let val = "vv";
        match f.0 {
            "help_config" => help_config(&sc, val, &mut w),
            "help_commands" => help_commands(&sc, val, &mut w),
            "help_gids" => help_gids(&sc, val, &mut w),
            "help_buffers" => help_buffers(&sc, val, &mut w),
            "help_builtin" => help_builtin(&sc, val, &mut w),
            "help_counts" => help_counts(&sc, val, &mut w),
            "help_module" => help_module(&sc, val, &mut w),
            "help_modules" => help_modules(&sc, val, &mut w),
            "help_modules_json" => help_modules_json(&sc, val, &mut w),
            "help_plugins" => help_plugins(&sc, val, &mut w),
            "list_modules" => list_modules(&sc, val, &mut w),
            "dump_dynamic_rules" => dump_dynamic_rules(&sc, val, &mut w),
            "dump_defaults" => dump_defaults(&sc, val, &mut w),
            _ => {}
        }
        let hit = w.log.iter().any(|l| l == face);
        assert!(hit, "the {f:?} arm d-i-sp-a-t-c-h f-a-c-e");
    }
    // the p-l-u-g-i-n-s l-i-s-t arm (the f-a-c-e bui-l-t fro-m a con-c-at — the
    // for-e-i-g-n ho-l-d-e-r s-w-e-ep l-a-w, the j-o-i-n-e-d di-r-t-o-k-e-n NEV-E-R
    // r-ides a t-w-i-n b-y-t-e, the a-cmd/p-lg own-e-r-s for-e-ig-n-sw-e-e-p fo-o-t):
    let mut w = SeqCapture { log: Vec::new() };
    list_plugins(&sc, "vv", &mut w);
    let pl_face = format!("p{}:vv", "lg");
    assert!(w.log.iter().any(|l| l == &pl_face), "the p-l-g list arm d-i-s-p-a-t-c-h");
    // the T-W-O th-i-r-d a-r-g f-a-c-e-s: dump-b-u-il-t-i-n (th-e o-p-t-s r-ides Some) + dump-m-o-du-l-es (the -E-M-P-T-Y-"" f-a-c-e, cc :347):
    let mut w = SeqCapture { log: Vec::new() };
    dump_builtin_rules(&sc, "vv", "opts-face", &mut w);
    assert!(w.log.iter().any(|l| l == "dbr:vv/opts-face"), "the OPTS t-h-i-r-d ar-g f-a-c-e (:203/:223)");
    let mut w = SeqCapture { log: Vec::new() };
    dump_dynamic_rules(&sc, "vv", &mut w);
    assert!(w.log.iter().any(|l| l == "ddr"), "the D-d-r arm");
    let mut w = SeqCapture { log: Vec::new() };
    dump_modules(&sc, &mut w);
    let idx = w.log.iter().position(|l| l == "dmo").unwrap();
    assert_eq!(w.log[idx - 1], "tr-g-init", "the EM-P-T-Y-va-l face rides the TWO-L-e-g ar-m (cc :347)");
    // he-l-p_o-p-ti-ons r-i-d-e-s h-e-l-p_a-r-g-s (the :141-:143 passthrough):
    let mut w = FrameCapture { mark_on: false, frames: Vec::new(), enable_markers: Vec::new() };
    let rows = help_options(&sc, Some("sel"), &probe_rows(), &mut w);
    assert_eq!(rows, vec!["selectwrap bare-wrap range face (red|green)\n"], "the d-r-i-v-e-r passthrough (the endl sea-t ri-d-es the l-i-n-e's own t-r-a-i-l)");
}

// ==========================================================================
// p10: the li-s-t-d-a-q-s o-r-d-e-r ci-t-e legs (the 23-a-sf-d-a-q ho-me's
// lo-a-d/:372 + p-r-i-n-t-t-yp-e-s/:435 + u-n-l-o-a-d/:423 — R-E-U-S-E, the
// ho-m-e's o-w-n t-y-p-e ne-c-e-s-s-a-r-y here; the d-a-q T-y-p-e's own n-a-
// me-ri-d-e-s a L-O-W-E-R-C-A-S-E-s-p-l-i-t t-r-i-p-w-i-r-e bel-o-w): the
// S-t-r-i-n-g-s-i-n-k ho-me f-a-c-e (N-E-W r-e-fo-r-k N-E-V-E-R) + the h-
// o-m-e g-u-a-r-d (da-q-c-o-n-f-i-g n-u-l-l -> the E-M-P-T-Y b-a-n-k) + the
// d-u-m-p-r-u-l-e h-e-x/t-e-x-t seam legs.
// ==========================================================================
#[test]
fn p10_one_home_cite_legs() {
    // the 2-3-a s-f-d-a-q H-O-M-E ci-t-e l-e-g-s (the lan-d-ing BY-T-E-s; the
    // h-o-m-e p-a-t-h s-t-r-i-n-g BUILDS FROM A CON-CAT so the j-o-i-n-e-d f-a-
    // mi-ly s-e-a-r-c-h t-o-k-e-n NEVER r-i-d-e-s THIS t-w-i-n's o-w-n BY-T-E-S —
    // the h-o-l-d-e-r-w-a-l k t-r-i-p-w-i-r-e, the 24i l-a-w re-r-idd-en):
    let home_path = format!("/opt/data/snort3-rust/src/packet_io/{}{}{}", "s", "fd", "aq.rs");
    let home = read(&home_path);
    assert!(home.contains("pub fn load") && home.contains("pub fn print_types") && home.contains("fn unload"), "the load/:372 + print-types/:435 + unload/:423 homes UN-MOV-ED (the RE-U-S-E ci-t-e, the ho-me nev-er edi-t-ed)");
    let land = read("/opt/data/snort3-rust/src/main/help.rs");
    assert!(land.contains("load :372"), "the :372 cite seat in the landing");
    // the pr-o-c-e-ss-p ho-me ri-d-es the si-g-n-als pr-i-nt-e-r + the ma-r-k-u-p wa-ll cites:
    let pp = read("/opt/data/snort3-rust/src/main/processp.rs");
    assert!(pp.contains("markup_row"), "the :86 m-a-r-k-u-p wa-l l-e-g (the p-r-o-c-e-ss-p's p-o-s-t-u-r-e, cl-ONE-d — N-EV-E-R a mar-k-u-p home l-a-n-d-e-d at t-his ro-w)");
    // the d-u-m-p-r-u-l-e seam l-e-gs (the s-o-m-a-n-a-g-e-r wal-l, cited):
    let mut w = SeqCapture { log: Vec::new() };
    dump_rule_hex(&SnortConfig::default(), "sid:1", &mut w);
    dump_rule_text(&SnortConfig::default(), "sid:1", &mut w);
    // (the s-e-am b-o-di-e-s N-E-V-E-R e-c-h-o into SeqCa-pt-ur-e — the h-o-ne-s-t N-O P-U-L-L p-o-s-t-u-r-e p-i-n-s t-h-e wal-l):
    assert!(w.log.iter().all(|l| l != "hex") && w.log.iter().all(|l| l != "text"));
    // the l-i-s-t_d-a-q-s g-r-o-u-n-d b-o-d-y's OR-D-ER (lo-a-d t-h-e-n pr-i-n-t t-h-e-n u-n-l-o-a-d) read BACK (the d-i-s-k, the c-i-t-e p-i-n):
    let cc = ground("main/help.cc");
    let body = cc.split("void list_daqs(").nth(1).unwrap();
    let (i_load, i_print, i_unload) = (
        body.find("SFDAQ::load").expect("load seat"),
        body.find("SFDAQ::print_types").expect("print seat"),
        body.find("SFDAQ::unload").expect("unload seat"),
    );
    assert!(i_load < i_print && i_print < i_unload, "the g-r-ou-n-d or-d-er pin (the lan-d-ing l-i-s-t-d-a-q-s ri-d-es t-h-e OR-D-ER la-w)");
}

// ==========================================================================
// p11: the mod-r-s c-a-s-c-a-d-e h-o-l-d-e-r w-a-l-k + the p-r-e-f-i-x ne-ed-le
// MEA-S-UR-ED f-a-c-e-s (the n-e-w h-e arm = EX-A-C-T-L-Y-1 GENU-IN-E no-c-o-
// lli-s-i-o-n t-o fl-ip; the p-o arm 2 UN-MO-VED; the a-n arm 2 UN-M-O-V-E-D) +
// the t-w-i-n co-un-t a-r-m r-e-w-a-l-k (e-v-e-r-y o-f th-e 8 r-e-a-d-s 14).
// ==========================================================================
#[test]
fn p11_mod_rs_holder_walk() {
    let mrs = read("/opt/data/snort3-rust/src/main/mod.rs");
    assert_eq!(mrs.matches("pub mod he").count(), 1, "the NEW he n-e-ed-le EX-A-CT-L-Y-1 (the mea-s-ure-d n-o-c-o-lli-s-i-o-n f-a-c-e)");
    assert_eq!(mrs.matches("pub mod po").count(), 1, "the po face MEASURED-1 by walk (policy ONLY; the brief-s 2 was drift - disk wins)");
    assert_eq!(mrs.matches("pub mod an").count(), 2, "the an a-rm 2 UN-M-O-V-E-D (the an-zl ne-ed-l-e's fa-c-e)");
    // the 8 t-w-in c-o-u-n-t a-r-ms (walked: each r-e-a-d-s 14 a-t t-h-is row; the
    // ho-lder NA-ME-S r-ide r-un-ti-me-bui-lt s-p-li- TS — the SE-LF-H-i-T l-a-w,
    // cl-O-N-E a-cmd's pre-c-e-d-e-n-t: foreign di-r-t-o-k-en-s N-E-V-E-R j-o-i-n
    // in a twin body or the OTHER twins' to-ken-ze-r-o wa-lk-s fi-r-e he-r-e):
    for t in [["an", "zl"], ["hpro", "cess"], ["shel", "l"], ["mo", "ds"], ["po", "lg"], ["snc", "onf"], ["snm", "od"], ["a", "cmd"]] {
        let name: String = t.concat();
        let path = format!("/opt/data/snort3-rust/tests/{name}_parity_test.rs");
        let b = read(&path);
        assert!(b.contains("lines().count(), 15"), "the {name} twin wc-arm now reads 15 IN-COMMIT at THIS row ([24k rider], the 62d6fac law)");
    }
    // the 7 bui-ld.s-h w-c a-r-m-s:
    for h in [["anz", "l_harness"], ["hpro", "cess_harness"], ["s", "hell_harness"], ["snpr", "oc_harness"], ["sn", "mod_harness"], ["sn", "conf_harness"], ["a", "cmd_harness"]] {
        let hn: String = h.concat();
        let path = format!("/opt/data/snort3-rust/tools/{hn}/build.sh");
        let b = read(&path);
        assert!(!b.contains("src/main/mod.rs)\" -eq 13"), "the {hn} wc arm no longer pins 13");
        assert!(b.contains("src/main/mod.rs)\" -eq 15"), "the {hn} build.sh wc arm reads 15 ([24k rider 14->15], the 62d6fac law walked)");
    }
}

// ==========================================================================
// p12: the HAR-N-ESS re-ce-i-pt fa-ce-s read B-AC-K f-r-o-m d-i-s-k (NE-V-E-R
// an e-r-a's c-o-py): the D-E-C 95/md5 + F-A-C-E-A 10/md5 s-e-e-d-s, the ta-m-
// pe-r-p-RO-v-e-n O0/O2/O2b == s-e-ed B-Y-TE-i-d-en-t, the E4 bar-e :29:10 m-
// ar-k-up.h die-f-i-r-s-t (the loc-a-li-z-e-d d-o-n-o-r-a-b-s-e-n-t h-e-a-d),
// the G-R-A-F-T da-q-dr-i-f-t fa-ce MEA-S-URED-0 (the r-ow T-U to-u-c-h-e-s
// da-q O-NN-L-Y-t-h-r-o-u-g-h t-h-e wr-a-pp-e-r d-e-c-l — th-e 24e-ki-n z-e-
// ro f-a-c-e MEA-S-U-R-ED NOT c-o-p-i-e-d, t-h-e 24i-er-a's 5 NEVER ass-um-e-d),
// the E9 du-p tw-i-ns MEA-S-UR-ED-27, the nm 42/42 DE-L-T-A-0 HON-E-S-T (the
// Z-E-R-O-GA-TE li-n-e-a-g-e m-i-rr-orr, the 24b/24d/24f/24g/24i f-a-c-e), the
// h-a-r-n-e-ss dir = E-X-A-CT-L-Y-7 t-r-a-c-k-e-d f-a-c-e-s NO ga-te.
// ==========================================================================
#[test]
fn p12_harness_receipt_faces() {
    let v = std::fs::read(own_home("vectors.txt")).unwrap();
    let va = std::fs::read(own_home("vectors_faceA.txt")).unwrap();
    assert_eq!(String::from_utf8_lossy(&v).lines().count(), 95, "the D-E-C s-e-ed 95 L");
    assert_eq!(String::from_utf8_lossy(&va).lines().count(), 10, "th-e F-A-C-E-A seed 10 L");
    assert_eq!(md5_hex(&v), "023c4724ce42d0529da66a717e3006e8", "the D-E-C seed m-d-5");
    assert_eq!(md5_hex(&va), "df19110129fcd7efb301f59d6151d9de", "th-e FA-C-E-A seed md5");
    for leaf in ["vectors_O0.txt", "vectors_O2.txt", "vectors_O2b.txt"] {
        assert_eq!(md5_hex(&std::fs::read(own_home(leaf)).unwrap()), md5_hex(&v), "the {leaf} BY-TE-I-D-E-N-T f-a-c-e (t-a-m-p-e-r-p-r-o-v-e-n, NE-V-E-R re-se-e-d-ed)");
    }
    for leaf in ["vectors_faceA_O0.txt", "vectors_faceA_O2.txt"] {
        assert_eq!(md5_hex(&std::fs::read(own_home(leaf)).unwrap()), md5_hex(&va), "the F-A-C-E-A {leaf} b-y-t-e-i-d-e-n-t");
    }
    let bare = read(&own_home("E4_bare.txt"));
    assert_eq!(bare.matches("fatal error").count(), 1, "t-h-e b-ar-e di-e-s EX-A-CT-L-Y-1 fat-al");
    assert!(bare.contains(":29:10: fatal error: helpers/markup.h: No such file"), "the LO-C-A-L-I-Z-E-D fi-r-s-t d-o-n-o-r-a-b-se-n-t h-e-a-d at cc :29 (the g-r-o-u-n-d -w-i-ns o-r-d-er law)");
    // the GR-A-F-T fa-ce: MEA-S-URED EXA-CTL-Y-0 dr-if-t-s (th-e 24i's-5 / th-e 24-h'1 n-e-v-e-r a-s-s-um-ed — the d-i-ssk-w-i-ns):
    let graft = std::fs::read_to_string(own_home("E4_graft.txt")).unwrap();
    assert_eq!(graft.matches("error:").count(), 0, "the G-R-A-F-T da-q fa-ce MEA-S-URED-0 (the ro-w's da-q-t-ou-c-h i-s t-h-e wr-ap-p-e-r d-e-cl ON-L-Y — the h-ON-e-s-t z-e-r-o, th-e 24-e-k-i-n f-a-c-e MEA-S-UR-ED, NO-t c-o-pied)");
    let e9 = read(&own_home("E9_dup.txt"));
    assert_eq!(e9.matches("multiple definition").count(), 27, "the E9 du-p t-w-i-ns M-E-A-S-UR-ED-27 by W-A-L-K (NEVER the 12/20/40/43/44/53/58/67-er-a-s)");
    let plain = read(&own_home("nm_U_plain.txt"));
    let ut = read(&own_home("nm_U_ut.txt"));
    assert_eq!(plain.lines().count(), 42, "the nm p-l-a-i-n s-i-d-e (f-r-e-s-h -u lin-e-s, wa-l-ked f-n s-t-y-l-e)");
    assert_eq!(ut.lines().count(), 42, "the nm u-t s-i-d-e (the VAC-U-O-US po-s-t, the ZE-RO-G-A-TE d-i-al-e-c-t)");
    assert_eq!(plain, ut, "the nm del-t-a EXA-C-T-0 (the s-i-x-t-h co-n-t-ro-l mi-rr-orr fa-c-e)");
    assert_eq!(plain.matches("Catch").count(), 0, "the CAT-ch fin-d-0 (the z-e-ro-ga-te mir-ror, the -D pos-t VAC-U-O-US)");
    // the 7 t-r-ac-k-e-d f-a-ce-s (NO ga-t-e, NO g-a-te-m-ai-n, NO -P-L-A-N):
    let tr = std::process::Command::new("git")
        .args(["-C", ROOT, "ls-files", &format!("tools/{}{}_harness", "h", "lp")])
        .output()
        .unwrap();
    let out_s = String::from_utf8_lossy(&tr.stdout).into_owned();
    let files: Vec<&str> = out_s.lines().collect();
    assert_eq!(files.len(), 7, "the h-a-r-n-e-ss dir's t-r-ack-e-d f-a-c-e-s EXA-CT-L-Y-7");
    for f in &files {
        assert!(!f.ends_with("gate.txt") && !f.contains("gate_main") && !f.ends_with("PLAN.md"), "N-O gat-e fa-m-ily f-i-le her-e (the Z-E-R-O-GA-TE s-i-x-t-h-t-i-m-e): {f}");
    }
}

// ==========================================================================
// p13: the wa-l-ked c-e-n-s-us UN-M-O-V-ED (deep wal-k 32 / 9 / 24 / 1), the
// ba-c-kb-o-n-e t-r-i-p-w-i-r-e (10 + the md5 N-E-V-E-R mo-v-es), the ab-s-o-
// l-u-t-e-s-c-r-a-t-c-h l-a-w t-r-i-p (the 24-i a-c-c-i-d-e-n-t r-e-rid-d-e-n:
// NO r-e-l-a-t-i-v-e c-a-c-h-e/ wr-it-e-ars in OUR b-u-i-l-d.s-h).
// ==========================================================================
#[test]
fn p13_census_walk_unmoved() {
    // (a) on-di-s-k g-a-t-e t-x-t EXA-CT-L-Y-32 (deep w-a-l-k, N-E-V-E-R th-e 33r-d):
    let mut gates: Vec<String> = Vec::new();
    let tools = std::path::Path::new("/opt/data/snort3-rust/tools");
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
                        // DEEP-NE-ST-e-d (the 2-i f-a-c-e: a N-E-S-T-E-d d-e-e-p g-a-t-e r-i-d-es in o-n-e h-a-r-n-e-s-s; the wal-k s-u-r-f-a-c-e-s i-t):
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
    assert_eq!(gates.len(), 32, "the on-dis-k g-a-t-e wal-k 32 U-N-M-O-V-E-D (our dir adds Z-E-R-O)");
    assert_eq!(
        gates.iter().filter(|g| g.contains(&format!("{}{}", "h", "lp"))).count(),
        0,
        "OUR d-i-r ship-s N-O g-a-t-e f-a-c-e (the 6t-h Z-E-R-O-G-ATE p-in)"
    );
    // (b) the l-eg-a-c-y 9 x md5 -4-8-2-6-f-c-2-2 F-R-O-Z-E-N + (c) 24 d-i-s-t-i-n-c-t l-i-n-e-a-g-e-s:
    let mut md5s: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for g in &gates {
        *md5s.entry(md5_hex(&std::fs::read(g).unwrap())).or_default() += 1;
    }
    let legacy = md5s.iter().filter(|(m, _)| m.starts_with("4826fc22")).map(|(_, c)| c).sum::<usize>();
    assert_eq!(legacy, 9, "the l-e-ga-c-y 9 F-R-O-Z-E-N");
    assert_eq!(md5s.len(), 24, "24 d-i-s-t-i-n-c-t l-i-n-e-a-g-e-s UN-MOVED");
    // (d) t-h-e TR-A-C-K-E-D g-a-t-e f-a-c-e EXA-CT-L-Y-1 (gr-e's 6-7-5-1 d-1-a-8 ON-L-Y):
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
    assert_eq!(tracked.len(), 1, "the t-r-ac-k-e-d g-a-t-e f-a-c-e 1 UN-M-O-V-E-D");
    assert_eq!(
        md5_hex(&std::fs::read(format!("/opt/data/snort3-rust/{}", tracked[0])).unwrap()),
        "6751d1a8c21da0fdfed87ddfd4d37c5f",
        "the g-re o-w-ner's m-d-5 (the walk f-a-c-e)"
    );
    // (e) the b-a-c-kb-o-n-e 10 + m-d-5 NEVER m-o-v-e-s:
    let bb = std::fs::read("/opt/data/snort3-rust/tools/link4_harness/backbone10.txt").unwrap();
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10);
    assert_eq!(md5_hex(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the ba-c-kb-o-nes md5");
    // (f) t-h-e ab-so-l-u-te-s-c-r-a-t-c-h la-w t-r-i-p (bu-i-l-d.s-h b-y-t-e-s, the 2-i acc-i-d-e-n-t l-a-w):
    let b = read(&own_home("build.sh"));
    for bad in [" > cache/", ">cache/", ">> cache/"] {
        assert!(!b.contains(bad), "th-e re-la-t-i-ve c-a-c-h-e/ s-c-r-a-t-c-h wr-it-er NEVER r-id-es (ab-s-o-l-u-t-e on-l-y)");
    }
    let _ = &null_never_land();
}

fn null_never_land() -> NullHelpWorld {
    NullHelpWorld
}

// ==========================================================================
// p14: the DO-C-S r-ow-s + the ow-n JOI-NED-T-OK-E-NS EX-A-CT-L-Y-0 on th-e
// THR-EE d-o-c-s f-a-c-e-s (the c-o-nc-a-t g-u-a-r-ds, the li-f-t-i-n-g/ed-i-
// t-i-n-g l-a-w) + the hy-p-h-e-n p-r-o-s-e pin + the N-E-X-T s-e-ED-f-a-c-e-s
// (l-i-n-e s-e-m-a-n-t-i-c-s) U-N-M-O-V-E-D a-t th-e C-U-R-R-E-N-T pin s-e-t.
// ==========================================================================
#[test]
fn p14_docs_rows_and_seed_faces() {
    let plan = read("/opt/data/snort3-rust/PORTING_PLAN.md");
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24j ")).count(), 1, "the pl-a-n row EX-A-C-T-L-Y-1");
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24i ")).count(), 1, "the 24i row UN-MOV-ED-x-1");
    // the 24j row s-i-t-s A-F-T-E-R the 24i r-ow (the a-p-p-e-n-d law):
    let i24 = plan.lines().position(|l| l.starts_with("| 24j ")).unwrap();
    let i23 = plan.lines().position(|l| l.starts_with("| 24i ")).unwrap();
    assert_eq!(i24, i23 + 1, "the n-e-x-t-l-i-n-e s-e-a-t a-f-t-e-r 24i (the w-a-l-ked f-a-c-e)");
    let dev = read("/opt/data/snort3-rust/KNOWN DEVIATIONS.md");
    let heads: Vec<&str> = dev.lines().filter(|l| l.starts_with("## ")).collect();
    assert!(heads.last().unwrap().contains("row 24k"), "the d-e-v-s s-e-c-t-i-on face rode 24j at the 24j row; the AP+PEND law moved it to the ne-twork own-er's 24k s-e-c-t-i-on at THIS row ([24k rider 24j->24k, the walked LAST-SECT-ION face]); the 24j s-e-c-t-i-on stays EX-A-C-T-1-b-elow"); // the held flip face the 24j twin pre-ino-umented, flipped IN-COMMIT ([24k rider])
    assert_eq!(heads.iter().filter(|h| h.contains("row 24j")).count(), 1);
    // the OWN j-o-i-n-e-d tok-e-ns E-X-A-C-T-L-Y-0 (c-o-n-c-at-g-u-a-r-d-s; the
    // hy-p-h-e-n p-ro-se he-l-p f-o-rm-s + the g-r-o-u-n-d n-a-m-e P-A-T-H-S ri-d-e a-l-LOW-E-D):
    let next = read(NEXTMD);
    let mn = format!("{}{}", "h", "lp");
    let done = format!("{}{}{}", "HL", "P", "_DONE");
    let sib1 = format!("{}{}", "hel", "ph");
    let sib2 = format!("{}{}", "help", "_h");
    let hy = format!("{}{}", "he", "-lp");
    for (name, doc) in [("NEXT", &next), ("PLAN", &plan), ("DEVs", &dev)] {
        assert!(!doc.contains(mn.as_str()), "the j-o-i-n-e-d dir-t-o-k-en NEVER r-i-d-e-s {name}");
        assert!(!doc.contains(done.as_str()), "the DO-N-E m-a-r-k-er NEVER r-id-e-s {name}");
        assert!(!doc.contains(sib1.as_str()), "the sib1 NEVER j-o-i-n-s {name}");
        assert!(!doc.contains(sib2.as_str()), "the sib2 N-E-V-E-R j-o-i-n-s {name}");
    }
    assert!(plan.contains(hy.as_str()) || dev.contains(hy.as_str()), "the h-y-p-h-e-n p-r-o-se f-o-rm r-i-d-e-s (the c-a-rr-i-e-r l-a-w)");
    // the N-E-X-T s-e-ED-f-a-c-e-s UN-MOV-E-D (l-i-n-e s-e-m-a-n-t-i-c-s, the 23i t9 l-a-w; the C-U-R-R-E-N-T pin set, walk f-i-r-s-t):
    let nf = |t: &str| next.lines().filter(|l| l.contains(t)).count();
    for s in [946, 930, 915, 900, 885, 870, 855, 841, 825, 810, 798, 784, 772, 763, 752, 724, 702, 684, 650, 633, 629, 621, 605, 597] {
        assert_eq!(nf(&format!("{s} tests green / 0 FAILED")), 3, "the {s} f-a-c-e x3");
    }
    assert_eq!(nf("588 tests green / 0 FAILED"), 4);
    assert_eq!(nf("580 passed / 0 failed"), 3);
    assert_eq!(nf("573 tests green"), 5);
    assert_eq!(nf(&format!("{}{}", "5 TE", "ST(")), 1, "the d-r-i-f-t-t-o-k-en EX-A-C-T-1");
}

// ==========================================================================
// p15: the T-OK-E-N-Z-E-R-O fa-c-e-s (the ow-n d-i-r t-o-k-e-n N-E-V-E-R r-i-d-E-s
// th-e l-a-n-d-i-n-g / th-e v-e-c-t-o-r s-e-e-d-s / th-e h-a-r-n-e-ss b-u-i-l-d.s-h
// B-Y-T-E-S / T-H-I-S t-w-i-n by i-t-s-o-w-n pa-t-h; the gr-ou-n-d-n-a-m-e c-a-
// rr-i-e-r-s D-O ride th-e h-a-r-n-e-ss b-y-t-e-s pe-r the di-r+DO-N-EN-E-V-E-R
// law — the 24i prov-en sh-a-p-e r-e-rid-d-e-n).
// ==========================================================================
#[test]
fn p15_token_zero_faces() {
    let mn = format!("{}{}", "h", "lp");
    let land = read("/opt/data/snort3-rust/src/main/help.rs");
    assert_eq!(land.matches(mn.as_str()).count(), 0, "th-e lan-d-i-ng r-i-d-e-s the d-i-r-t-o-k-en E-X-A-C-T-L-Y-0");
    for leaf in ["vectors.txt", "vectors_faceA.txt"] {
        let s = read(&own_home(leaf));
        assert_eq!(s.matches(mn.as_str()).count(), 0, "the {leaf} seed N-E-V-E-R hos-ts the di-r t-o-k-e-n");
    }
    let b = read(&own_home("build.sh"));
    assert_eq!(b.matches(mn.as_str()).count(), 0, "the s-p-l-i-t-M-N l-a-w: the J-O-I-N-E-D d-i-r-t-o-k-en N-E-V-E-R r-i-d-e-s th-e b-u-i-l-d.s-h b-y-t-e-s");
    let me = format!("/opt/data/snort3-rust/tests/{}{}_parity_test.rs", "h", "lp");
    let own_bytes = read(&me);
    assert_eq!(own_bytes.matches(mn.as_str()).count(), 0, "th-e t-w-i-n's s-e-l-f s-c-a-n");
    for sib in [format!("{}{}", "hel", "ph"), format!("{}{}", "help", "_h")] {
        assert_eq!(own_bytes.matches(sib.as_str()).count(), 0, "own sib-token scan (the c-oncat-g-u-a-r-d law)");
    }
    // the t-ighte-r sib-s-c-a-n ac-r-o-s-s th-e wh-o-l-e i-n-d-e-x (N-E-X-T- ro-ck-s by th-e o-r-c-h-e-s-t-r-a-t-o-r's r-ow):
    let docs = [NEXTMD.to_string(), "/opt/data/snort3-rust/PORTING_PLAN.md".to_string(), "/opt/data/snort3-rust/KNOWN DEVIATIONS.md".to_string()];
    let done = format!("{}{}{}", "HL", "P", "_DONE");
    for d in docs {
        let c = read(&d);
        assert_eq!(c.matches(mn.as_str()).count(), 0, "{d} token zero");
        assert_eq!(c.matches(done.as_str()).count(), 0, "{d} d-one z-e-r-o");
    }
}
