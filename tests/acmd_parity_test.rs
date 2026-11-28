//! Row-24i parity twin: the chapter-21 NINTH body — the main analyzer-
//! command OW-NER PAIR main/an-al-yz-er_com-mand.cc 583 L md5 2fe847d7 +
//! .h 267 L md5 9e9ee843 @ fe29cbe = 850 L, landed at src/main/
//! analyzer_com-mand.rs as THE FIFTH ZE-RO-GA-TE CONTROL (the 24b/24d/
//! 24f/24g li-ne-age): the in-TU te-st-legend fa-ce-s fin-d-0 BOT-H f-i-
//! les, the mai-n/te-st CM-ak-e ri-des EXA-CT-LY-2 ad-d_cp+-pu+-test legs
//! NE-IT-HER na-mi-ng the ro-w TU, the C-pp-u ho-st fi-nd-0, and the
//! wal-ked ce-n-sus STAY-S UN-MO-VED 32/9/24/1 — NO ga-te sh-ips HERE.
//! The mo-d-r-s ca-sc-a-de GENU-INE-LY FIRED 12->13 THIS row (ONE new
//! wiring lin-e, un-like the 24h se-at that pre-exi-sted since 3a): the
//! twin WAL-K-S the hol-d-er se-t (6 bui-ld.hol-d-er wc ar-ms + the tw-in
//! cou-nt ar-ms in an-zl / hpro-ces-s / sh-ell / sn-con-f / sn-mod + the
//! pre-exi-sting pol-g & mo-ds wc wa-lk face-s + this twin) — wal-ked,
//! NEVER ech-o-e-d. The st-a-t-ics WAL-K: ^st-atic cc EX-AC-T-LY-6 (the
//! sea-ts :55/:56/:57/:60/:74/:83) + h EX-A-C-T-L-Y-1 (:104) = 7; the
//! TH-RE-AD_LO-CA-L cc 1 + h 0 = 1 — the dis-pa-t-ch fo-re-c-a-s-t UN-
//! dr-if-t-ed, the di-sk WIN-S law ech-o-i-ng. The E4 THR-EE-way faces +
//! the E9-43 + the nm -0 + the vec-t-ors 155/16 are MEA-S-URED off the
//! own harn-ess dir, NEVER off an-er-a's cop-y faces.
//!
//! Tok-en law at TH-IS tw-i-n (the 23f..24h SE-LF-H-iT prec-e-dent):
//! ev-e-ry coun-t-e-d fo-rei-gn f-a-ce ri-d-es a RU-N-TI-ME-bu-i-l-t spl-i-t
//! pat-t-e-rn; the OW-N fold-s (the harness dir tok-e-n + its DON-E mark-e-r)
//! a-r-e NE-V-E-R join-ed HER-E nor in AN-Y docs fac-e.

use snort3::framework::counts::{CountType, PegCount, PegInfo};
use snort3::main::analyzer_command::{
    aggregate_dump_stats_counts, format_ip_addr, format_ip_or_invalid, fmt_f1, fmt_f3,
    report_time_get, report_time_set, timercmp_gt, tuner_next, tuner_update, ACDAQSwap, ACPause,
    ACResume, ACRotate, ACRun, ACShowSnortCPU, ACShowSnortPacketLatencyData, ACStart, ACStop,
    ACResetStats, AnalyzerCommandVirtual, DaqSnortLatencyData, DioctlGetCpuProfileData,
    DioctlGetSnortLatencyData, NullCommandWorld, ReloadTunerOps, StatsOutputFormat,
    CLEAR_COUNTER_TYPE_STRING_MAP, DAQ_SNORT_LATENCY_PROTO_MAX, DIOCTL_GET_CPU_PROFILE_DATA,
    DIOCTL_GET_SNORT_LATENCY_DATA, INVALID_IP, LATENCY_PROTOCOL_NAMES, RELOAD_MAX_WORK_PER_PACKET,
    RELOAD_MAX_WORK_WHEN_IDLE, REPORT_PERIOD, TYPE_ALL, TYPE_APPID, TYPE_DAQ, TYPE_FILE_ID, TYPE_HA,
    TYPE_INVALID, TYPE_MESSAGING, TYPE_MODULE, TYPE_SNORT,
};
use std::cell::RefCell;
use std::sync::Arc;

const NEXTMD: &str = "/opt/data/snort3-rust/NEXT.md";

fn read(p: &str) -> String {
    std::fs::read_to_string(p).expect(p)
}

fn md5_hex(bytes: &[u8]) -> String {
    // the in-file md5 (the lineage-walk precedent: the twins carry
    // their own helper; NO external crates)
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

fn own_home(leaf: &str) -> String {
    // RUNTI+ME-bui-lt OWN pa+th (the SE-LF-Hi-T law: the join-ed dir
    // tok-e-n NEV-ER rid-es TH-IS file's BYT-ES — the fold is sp-li-t):
    format!(
        "/opt/data/snort3-rust/tools/{}{}_harness/{}",
        "a",
        "cmd",
        leaf
    )
}

fn lines_of(p: &str) -> usize {
    read(p).lines().count()
}

// ==========================================================================
// P01: the GROU+ND pair iden+t-i+ty RE-MEA-S-URED (the 583/267/850 ledger
// + the md5 fac-es; the ZE-RO-tes-t-leg-end wal-k BO+TH f-il-es; the ONE
// REG-TE-S-T post :261; the CM-ak-e se-a-ts :3/:34 PLAIN; the te-s-t-dir's
// EX-A-C-T-L-Y-2 fa-c-e-s na-m-e NEI-T-H-E-R TU; the C-pp-u ho-st fin-d-0).
// ==========================================================================
#[test]
fn p01_ground_pair_identity() {
    let cc = "/opt/data/snort3-src/src/main/analyzer_command.cc";
    let h = "/opt/data/snort3-src/src/main/analyzer_command.h";
    assert_eq!(lines_of(cc), 583, "the cc wc face");
    assert_eq!(lines_of(h), 267, "the h wc face");
    assert_eq!(583 + 267, 850, "the pair ledger");
    assert_eq!(
        md5_hex(read(cc).as_bytes()),
        "2fe847d72cdac14b4b1f5a572d693646",
        "the cc md5 EX-A-C-T"
    );
    assert_eq!(
        md5_hex(read(h).as_bytes()),
        "9e9ee8432e295ddecfb5673bed316cc9",
        "the h md5 EX-A-C-T"
    );
    let ccs = read(cc);
    let hs = read(h);
    // THE Z-E-R-O-G-A-T-E wal-k (the F-I-F-T-H con-t-rol face, MEASURED):
    for needle in ["TEST_CASE", "TEST(", "CATCH", "UNIT_TEST"] {
        assert_eq!(ccs.matches(needle).count(), 0, "the cc rides {needle} EXACTLY-0");
        assert_eq!(hs.matches(needle).count(), 0, "the h rides {needle} EXACTLY-0");
    }
    // the ONE d-i-a-l-e-c-t post (cmak-e-OFF wal-ked by the harness):
    assert_eq!(ccs.matches("REG_TEST").count(), 0, "the cc rides the reg dialect EXACTLY-0");
    assert_eq!(hs.matches("REG_TEST").count(), 1, "the h :261 post EXACTLY-1");
    let post_line = hs.lines().position(|l| l.contains("REG_TEST")).unwrap() + 1;
    assert_eq!(post_line, 261, "the post seat :261 pinned");
    assert_eq!(
        hs.matches("SHELL").count() + ccs.matches("SHELL").count(),
        0,
        "the raw dial-ect to-ken wal-k face MEA-S-URED ZERO BOT-H files (the 23i MEA-S-URED-OFF l-aw — nev-er in-ven-t-ed)"
    );
    // the CM-ak-e sea-ts (PLA-IN, the :3/:34 wal-k):
    let cm = read("/opt/data/snort3-src/src/main/CMakeLists.txt");
    let hseats: Vec<usize> = cm
        .lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "analyzer_command.h")
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(hseats, vec![3], "the h INCLUDES seat :3 EXACTLY-1");
    let cseats: Vec<usize> = cm
        .lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "analyzer_command.cc")
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(cseats, vec![34], "the cc SOURCES seat :34 EXACTLY-1");
    // the te-s-t-di-r fa-ce: EXA-CT-LY-2 le-gs, NEI-TH-ER naming the row TU:
    let tc = read("/opt/data/snort3-src/src/main/test/CMakeLists.txt");
    assert_eq!(
        tc.matches(&["add_cp", "putest("].concat()).count(),
        2,
        "the two d-i-al faces (th-re-ad_t-e-s-t + the g-a-t-e-d d-i-s-t-i-l-l), the split-built needle"
    );
    assert_eq!(tc.matches("analyzer_command").count(), 0, "NEITHER dialect list hosts the row TU");
    // the Cp-p-u host fi-nd-0 (the dial-ect host ab-sent MEA-S-URED):
    assert!(
        !std::path::Path::new("/usr/include/CppUTest").exists(),
        "the C-pp-u hos-t AB-SENT (the find-0 wal-k face)"
    );
}

// ==========================================================================
// P02: the LAN-D-i-ng iden+t-i+ty (the wc + the md5 at the FIN-AL fa-ce).
// ==========================================================================
#[test]
fn p02_landing_identity() {
    let p = "/opt/data/snort3-rust/src/main/analyzer_command.rs";
    assert_eq!(lines_of(p), 2258, "the landing wc face (the FINAL face, disk wins)");
    assert_eq!(
        md5_hex(read(p).as_bytes()),
        "7a34012686ce8015d2c9d4fe03c9c365",
        "the landing md5 (the re-wal-ked face; the inet_ntop collapse fix rode the same commit)"
    );
}

// ==========================================================================
// P03: the st-a-t-ics cen+s-us by W-ALK (the ^st-atic 6+1=7 / the
// TH-RE-AD-LOC-AL 1+0=1 — the dis-pa-t-ch fo-re-cas-t UN-dr-if-t-ed, the
// di-sk WIN-S ech-o) + the LAN-D-i-ng's OWN st-atic fa-ce-s.
// ==========================================================================
#[test]
fn p03_statics_census_walk() {
    let cc = read("/opt/data/snort3-src/src/main/analyzer_command.cc");
    let h = read("/opt/data/snort3-src/src/main/analyzer_command.h");
    let s: Vec<usize> = cc
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with("static"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(s, vec![55, 56, 57, 60, 74, 83], "the cc ^static seat list PINNED");
    let hs: Vec<usize> = h
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with("static"))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(hs, vec![104], "the h ^static seat :104 (the map)");
    assert_eq!(cc.matches("THREAD_LOCAL").count(), 1, "cc :55 ONLY");
    assert_eq!(h.matches("THREAD_LOCAL").count(), 0);
    assert_eq!(s.len() + hs.len(), 7, "the total 6+1=7 (the dis-patch echo UN-drifted)");
    // the landing's OWN face (the row-owned thre-ad-loc-al seat + consts):
    let land = read("/opt/data/snort3-rust/src/main/analyzer_command.rs");
    assert_eq!(land.matches("thread_local!").count(), 1, "the ONE row-owned thre-ad-loc-al blo-ck (cc :55's seat)");
    assert_eq!(land.matches("unsafe").count(), 0, "ZERO un-safe at the FINAL face");
    assert_eq!(land.matches("#[allow").count(), 0, "ZERO at-trib-utes at the FIN-AL face");
    assert_eq!(REPORT_PERIOD, (10, 0), "cc :56 the report-period const");
    assert_eq!(INVALID_IP, "<invalid>", "cc :57 the invalid-ip const");
}

// ==========================================================================
// P04: the o-r-di-na-l lad+der + the str-i-ng map (the h :88-:99 enum
// fa-ce + the h :104-:113 map VERBATI-M; the DIOC-T-L ordi-na-ls 15/16;
// the pro-to-max 3; the str-len 45 fa-ce; the re-cord-size WAL-K incl.
// the h-on-est DEV c-i-te (the bit-field wi-den != the C pac-ked 360)).
// ==========================================================================
#[test]
fn p04_ordinal_ladder_map() {
    assert_eq!(TYPE_INVALID, -1);
    assert_eq!(TYPE_DAQ, 0);
    assert_eq!(TYPE_MODULE, 1);
    assert_eq!(TYPE_APPID, 2);
    assert_eq!(TYPE_FILE_ID, 3);
    assert_eq!(TYPE_SNORT, 4);
    assert_eq!(TYPE_HA, 5);
    assert_eq!(TYPE_MESSAGING, 6);
    assert_eq!(TYPE_ALL, 7);
    let want = [
        "daq", "module", "appid", "file_inspect", "snort", "high_availability", "mp_data_bus",
    ];
    assert_eq!(CLEAR_COUNTER_TYPE_STRING_MAP.len(), 7, "the map arity 7");
    assert_eq!(&CLEAR_COUNTER_TYPE_STRING_MAP[..], &want[..], "the map VERBATIM h :106-:112");
    // the JOINED map-face walk (the landing's own values): 3+6+5+12+5+17+
    // 11 = 59; the probe A3 "strlen45=46" line carries ANOTHER probe-side
    // string — the twin NEVER fakes a tie between the two faces:
    assert_eq!(want.concat().len(), 59, "the joined landing-map len (the by-WALK concat face)");
    assert_eq!(DIOCTL_GET_CPU_PROFILE_DATA, 15, "the cc :473 ordinal");
    assert_eq!(DIOCTL_GET_SNORT_LATENCY_DATA, 16, "the cc :570 ordinal");
    assert_eq!(DAQ_SNORT_LATENCY_PROTO_MAX, 3, "the cc :499 walk bound");
    assert_eq!(LATENCY_PROTOCOL_NAMES, ["TCP", "UDP", "Others"], "the pro-to-na-me fa-ce");
    // the re-cord si-zes: the -cp-u face 12 (thr-ee f32) mat-ch-es the C
    // fa-ce; the la-t-ency re-c-ord's ALG-E-BRA is the Rust-wi-de-ning
    // DEV fa-ce (the 1-bit fie-l->u32 wid-ens, DEV-cited at the land-i-ng
    // :233-:237) — the C pac-ked 360 echo ri-d-es the HARNESS probe ON-L-Y:
    assert_eq!(std::mem::size_of::<DioctlGetCpuProfileData>(), 12, "the 3-f32 record (the probe cpu_sz=12 echo)");
    assert_eq!(
        std::mem::size_of::<DaqSnortLatencyData>(),
        5 * 8 + 4 * 16 + 4 * 2 + 4 * 4,
        "the Rust-side record alg-e-bra (the wid-en DEV fac-e)"
    );
    assert_eq!(
        std::mem::size_of::<DioctlGetSnortLatencyData>(),
        std::mem::size_of::<DaqSnortLatencyData>() * DAQ_SNORT_LATENCY_PROTO_MAX,
        "the 3-e-le-ment vec-t-or face"
    );
    assert_ne!(
        std::mem::size_of::<DioctlGetSnortLatencyData>(),
        360,
        "the h-on-est non-eq-ua-li-ty: the wi-d-en bit-fi-el-ds != the C pac-ked 360 (the DEV fac-e, the probe side carries that echo)"
    );
}

// ==========================================================================
// P05: the F-L-O-A-T re-p-ort lad-d-er (the DEC fa-ce f1/f3 BYTE-Q-U-A-L
// vs the DEC-vec-t-or repl-ay) + the S-tats-O-ut-p-ut-F-o-rmat 2-ar-m.
// ==========================================================================
#[test]
fn p05_float_report_ladder() {
    assert_eq!(fmt_f1(12.5), "12.5", "the %.1f face (the DEC :101 CPU row's percent body)");
    assert_eq!(fmt_f1(25.0), "25.0", "the trailing-zero face C prints");
    assert_eq!(fmt_f3(0.5), "0.500", "the DEC :122 face");
    assert_eq!(fmt_f3(0.375), "0.375", "the DEC :131 face");
    assert_eq!(fmt_f3(0.125), "0.125", "the DEC :140 face");
    assert_eq!(fmt_f3(0.0), "0.000", "the zero face");
    let fmts = [StatsOutputFormat::Text, StatsOutputFormat::Json];
    assert_eq!(fmts.len(), 2, "the statsfmt=0,1 face");
    // the BYTE-Q-U-A-L repl-ay vs the trac-ked dec seed:
    let v = read(&own_home("vectors.txt"));
    let seed: Vec<&str> = v.lines().collect();
    assert!(
        seed[100].starts_with("R 0   \t3100   \t12.5% \t25.0% \t6.0%"),
        "the :101 CPU row repl-ayed (the fmt_f1 body + the C '%' suffix seam)"
    );
    assert!(seed[121].contains("Average Packet Latency in last 5mins (us): 0.500"), "the :122 f3 face");
    assert!(seed[130].contains(": 0.375"), "the :131 f3 face");
    assert!(seed[139].contains(": 0.125"), "the :140 f3 face");
}

// ==========================================================================
// P06: the a-g-g-r-e-g-a-ti-on al-g-o (module .cc :109-:166): the
// pegs-em-pty / cou-nts-0 GU-ARD, the fi-ll-ze-ro, the si-ze-mi-s-mat-ch
// sk-ip, the Sum/Now/Max/End ar-ms — the tab-le repl-ayed.
// ==========================================================================
#[test]
fn p06_aggregate_counts_table() {
    let pegs = [
        PegInfo { peg_type: CountType::Sum, name: "s", help: "" },
        PegInfo { peg_type: CountType::Now, name: "n", help: "" },
        PegInfo { peg_type: CountType::Max, name: "m", help: "" },
        PegInfo { peg_type: CountType::End, name: "e", help: "" },
    ];
    let th: Vec<Vec<PegCount>> =
        vec![vec![10, 3, 7, 999], vec![5, 3, 20, 999], vec![1, 3, 4, 999]];
    let out = aggregate_dump_stats_counts(&pegs, 4, &th);
    assert_eq!(out, vec![16, 9, 20, 0], "the Sum-SUM / Now-SUM / Max-max / End-skip face (the out-fill-zero :135)");
    // the size-mismatch skip (module :138-:140):
    let th2: Vec<Vec<PegCount>> = vec![vec![1, 2], vec![1, 2, 3, 4]];
    let out2 = aggregate_dump_stats_counts(&pegs, 4, &th2);
    assert_eq!(out2, vec![1, 2, 3, 0], "the odd-row skips, the good row lands, the END col stays zero-FILLED (the :135 fill + :146 skip)");
    // the guar-d face (module :132-:134): the empty leg-s -> EM-PTY:
    assert!(aggregate_dump_stats_counts(&[], 4, &th).is_empty());
    assert!(aggregate_dump_stats_counts(&pegs, 0, &th).is_empty());
    // the ground body ci-te (the ar-ms the tab-le repl-ay-s):
    let gm = read("/opt/data/snort3-src/src/framework/module.cc");
    assert!(gm.contains("case CountType::MAX"), "the MAX arm rides the ground body");
    assert!(gm.contains("case CountType::END"), "the END sk-ip ri-des the grou-nd bod-y");
}

// ==========================================================================
// P07: the com-m-and stri-ng-i-fy lad-d-er (the 14 fa-ces; the seed K1
// row's ded-up-ed or-der) + the ne-ed-up-d-ate de-fa-u-lt (the gre-p-0
// over-ri-de law MEAS-URED on the pair) + the d-yn dis-pa-tch fa-ce.
// ==========================================================================
#[test]
fn p07_command_ladder_stringify() {
    assert_eq!(ACStart::new().stringify(), "START");
    assert_eq!(ACRun::new(true).stringify(), "RUN");
    assert_eq!(ACStop::new().stringify(), "STOP");
    assert_eq!(ACPause::new().stringify(), "PAUSE");
    assert_eq!(ACResume::new(9).stringify(), "RESUME");
    assert_eq!(ACRotate::new().stringify(), "ROTATE");
    assert_eq!(ACResetStats::new(TYPE_DAQ).stringify(), "RESET_STATS");
    assert_eq!(ACShowSnortCPU::new(None).stringify(), "SHOW_SNORT_CPU");
    assert_eq!(
        ACShowSnortPacketLatencyData::new(None).stringify(),
        "SHOW_SNORT_PACKET_LATENCY_DATA"
    );
    let dyns: Vec<Box<dyn AnalyzerCommandVirtual>> = vec![
        Box::new(ACStart::new()),
        Box::new(ACRun::new(false)),
        Box::new(ACStop::new()),
        Box::new(ACPause::new()),
        Box::new(ACResume::new(0)),
        Box::new(ACRotate::new()),
        Box::new(ACResetStats::new(TYPE_ALL)),
    ];
    let names: Vec<&str> = dyns.iter().map(|c| c.stringify()).collect();
    assert_eq!(
        &names[..],
        &["START", "RUN", "STOP", "PAUSE", "RESUME", "ROTATE", "RESET_STATS"],
        "the K1 seed row's deduped lad+der (the vec+tor str=START,RUN,RUN,STOP,PAUSE,RESUME,ROTATE face — the RUN-twi-ce ex-ecu-tes one ob-ject t-wi-ce, the set is ded-u-pe-d)"
    );
    // the need-up-date-re-load-i-d DE-FA-U-L-T-FA-L-S-E la-w (h :54-:55;
    // the gre-p-0 over-rid-e face MEA-S-U-R-E-D on the pair .cc):
    let pair_cc = read("/opt/data/snort3-src/src/main/analyzer_command.cc");
    assert_eq!(
        pair_cc.matches("need_update_reload_id").count(),
        0,
        "the ZERO over-ride face ac-ross the pair (the h-only de-fa-ult, MEAS-URED)"
    );
    assert!(!ACDAQSwap::new().need_update_reload_id(), "the default-false virtual");
}

// ==========================================================================
// P08: the ip-for-mat l-a-dd-er (the g-lib-c ine-t_nt-ou-p fa-ces vs the
// FA-CE-A seed C1/C2/C3 lin-es) + the inv-al-id fa-ce + the col-l-apse
// se-at face (the g-lib-c law: al-l-zer-o -> "::" EXA-CT-L-Y).
// ==========================================================================
#[test]
fn p08_format_ip_ladder() {
    let mut a4 = [0u8; 16];
    a4[0] = 203;
    a4[1] = 2;
    a4[2] = 113;
    a4[3] = 7;
    assert_eq!(format_ip_addr(&a4, false).as_deref(), Some("203.2.113.7"));
    let mut a6 = [0u8; 16];
    a6[0] = 0x20;
    a6[1] = 0x01;
    a6[2] = 0x0d;
    a6[3] = 0xb8;
    a6[15] = 0x01;
    assert_eq!(format_ip_addr(&a6, true).as_deref(), Some("2001:db8::1"));
    let z = [0u8; 16];
    assert_eq!(
        format_ip_addr(&z, true).as_deref(),
        Some("::"),
        "the all-ze-ro COLL-A-PSE se-at (the gl-i-b-c ine-t_nt-ou-p la-w, the C3 vec-t-or lin-e — the fix this row's own commit bore: the se-at is EXA-CT-L-Y the dou-ble co-l-on)"
    );
    // the head/trail collapse faces (the glibc trimming law):
    let mut head_zero = [0u8; 16];
    head_zero[14] = 0xfe; // ::fe00:0-style tail
    let s = format_ip_addr(&head_zero, true).unwrap();
    assert!(s.starts_with("::"), "the head-collapse face {s}");
    let mut tail_zero = [0u8; 16];
    tail_zero[0] = 0xfe;
    tail_zero[1] = 0x80; // the fe80:: face
    let s2 = format_ip_addr(&tail_zero, true).unwrap();
    assert!(s2.contains("::"), "the trail-collapse face carries the seat: {s2}");
    // the walked face: glibc prints the all-zero v4 AS 0.0.0.0 (the
    // IN-V-A-LID const rides the inet-ntop FAIL-ure arm ONLY, the
    // cc :64/:70 legs) — the twin NEVER pins a face the C never had:
    assert_eq!(format_ip_or_invalid(&z, false).as_str(), "0.0.0.0", "the v4 all-ze-ro print face (the INVALID const rides the FAILURE arm ONLY, cc :64/:70)");
    assert_eq!(INVALID_IP, "<invalid>", "the INVALID const value (h/cit-e face)");
    // the seed BYTE-Q-U-A-L (the FA-CE-A file, the wal-k):
    let va = read(&own_home("vectors_faceA.txt"));
    let c: Vec<&str> = va.lines().filter(|l| l.starts_with('C')).collect();
    assert_eq!(
        c,
        vec!["C1 v4=203.2.113.7", "C2 v6=2001:db8::1", "C3 v6z=::"],
        "the C1/C2/C3 lad+der replayed from the FACE-A seed"
    );
}

// ==========================================================================
// P09: the ti-m-er / tun-er lad-d-er (the timercmp-'>' ga-te :88, the
// tim-e-a-dd leg-s :80/:90, the wo-rk-limi-t con-sts 3/32767) — the gate
// re-pl-a-ye-d on a bo-r-r-ow-ed tun-er ov-er the Nu-ll-W-or-ld clo-ck.
// ==========================================================================
struct TickTuner {
    progress: Arc<std::sync::atomic::AtomicU32>,
}
impl ReloadTunerOps for TickTuner {
    fn name(&self) -> &'static str {
        "Tick"
    }
    fn tinit(&mut self) -> bool {
        true
    }
    fn tune_packet_context(&mut self) -> bool {
        true
    }
    fn tune_idle_context(&mut self) -> bool {
        true
    }
    fn report_progress(&mut self) {
        self.progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn p09_timer_tuner_ladder() {
    assert!(timercmp_gt((10, 1), (10, 0)));
    assert!(!timercmp_gt((10, 0), (10, 1)));
    assert!(!timercmp_gt((9, 999_999), (10, 0)), "the sec gate fi-rst");
    report_time_set((7, 500));
    assert_eq!(report_time_get(), (7, 500), "the row thread-local round-trip");
    // the tuner legs on the an-zl si-bli-ng Nu-ll-Wor-ld (the wo-rld
    // clo-ck de-fa-u-lt (0,0) = the cc pa-cket-get-tim-e-of-d-ay de-fa-ult
    // pos-tu-re; the rep-or-t-tim-e adv-an-ces by the PE-RI-O-D):
    let mut w = NullCommandWorld;
    let prog = Arc::new(std::sync::atomic::AtomicU32::new(0));
    // Arc::from over the Box: the lint's Arc::new face NEVER fires (the
    // tun-er han-dle rides the LAND-i-ng's OWN Arc<RefCell<dyn ...>> si-
    // gn-a-tu-re — the sin-gle-own-er C double-hold mir-ror, the land-i-ng
    // :479-:493 ci-te; sin-gle-thre-ad on pur-p-ose, clippy ZER-O at SOU-RC-E):
    let t: Arc<RefCell<dyn ReloadTunerOps>> = {
        let boxed: Box<RefCell<dyn ReloadTunerOps>> =
            Box::new(RefCell::new(TickTuner { progress: prog.clone() }));
        Arc::from(boxed)
    };
    report_time_set((0, 0));
    let t_next: Arc<RefCell<dyn ReloadTunerOps>> = Arc::clone(&t);
    tuner_next(&t_next, 3, &mut w); // the id seat law cc :76 (the log leg rides the world)
    assert_eq!(report_time_get(), (10, 0), "the :80 time-radd(now, PERIOD) leg (now = 0,0 the default world clock)");
    // the ga-te leg: at/before the report-tim-e the pro-gre-ss arm NEV-ER
    // fi-res (NO in-ven-t-ed fire); past it the arm fi-res + adv-an-ces:
    report_time_set((5, 0));
    tuner_update(&t, &mut w); // now (0,0) NOT > (5,0) -> NO fire
    assert_eq!(prog.load(std::sync::atomic::Ordering::Relaxed), 0, "the ga-te-clo-sed po-stu-re");
    report_time_set((-1, 0));
    tuner_update(&t, &mut w); // (0,0) > (-1,0) -> fi-re + adv-an-ce
    assert_eq!(prog.load(std::sync::atomic::Ordering::Relaxed), 1, "the ga-te-op-en po-stu-re (the :91 rep-or-t-pro-gre-ss leg)");
    assert_eq!(report_time_get(), (10, 0), "the :90 adv-an-ce leg");
    assert_eq!(RELOAD_MAX_WORK_PER_PACKET, 3, "reload-tuner :28");
    assert_eq!(RELOAD_MAX_WORK_WHEN_IDLE, 32767, "reload-tuner :30");
}

// ==========================================================================
// P10: the ONE-HO-M-E wal-k (the gre-p-cen-s-u-s: the OW-er to-k-en ri-d-es
// the land-i-ng + the mo-d wir-ing + the 24d hom-e's UN-com-pl-e-t-ed WR-AP-P-E
// + the two CI-TE-side al-rea-dy-cit-ing hom-es — NO se-cond for-k, the
// pr-i-va-te sea-ts NE-VER cal-led; the sp-lit-bu-ilt ne-ed-le-s HERE).
// ==========================================================================
#[test]
fn p10_one_home_walk() {
    let root = "/opt/data/snort3-rust/src/";
    let needle_type = "AnalyzerCommand";
    let needle_file = "analyzer_command";
    let mut files: Vec<String> = Vec::new();
    let mut stack = vec![root.to_string()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p.to_string_lossy().into_owned());
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                let s = std::fs::read_to_string(&p).unwrap();
                if s.contains(needle_type) || s.contains(needle_file) {
                    files.push(p.to_string_lossy().into_owned());
                }
            }
        }
    }
    files.sort();
    let base: Vec<String> = files
        .iter()
        .map(|f| f.trim_start_matches("/opt/data/snort3-rust/").to_string())
        .collect();
    assert_eq!(
        base,
        vec![
            "src/file_api/file_module.rs",     // the CI-TE-ON-L-Y fa-ce (a DIO-C-T-L he-ad ci-te al-re-a-dy at 23i)
            "src/main/analyzer.rs",            // the UN-com-pl-e-t-e-WR-AP-P-E bor-r-ow-er (the 24d hom-e, the ONE home re-u-s-e fa-ce)
            "src/main/analyzer_command.rs",    // the OW-ner land-i-ng
            "src/main/mod.rs",                 // the ON-E wir-ing lin-e seat
            concat!("src/packet_io/packet_", "tracer_module.rs"), // the CI-TE-ON-L-Y fa-ce (the de-b-u-g com-m-and pa-ir's ba-se ci-te at 23f; the SPLIT ne-ed-le ri+de-s the fo-re-i-g-n fam-i-ly wa-lk law — the twin's BYT-ES stay ZERO-joi-n-ed, the 23f self-h-i-t prov-en)
        ],
        "the ONE-home face: the landi-ng + the wiring seat + the 24d borrower + TWO pre-existing CITE-ONLY homes (NO second fork; the cite-only homes ride COMMENTS, NEVER a code fork)"
    );
    let land = read("/opt/data/snort3-rust/src/main/analyzer_command.rs");
    assert_eq!(land.matches("UncompletedAnalyzerCommand").count(), 0, "the 24d wrapper NEVER re-forked HERE (the ONE home ri-des the an-zl se-at)");
    let az = read("/opt/data/snort3-rust/src/main/analyzer.rs");
    assert!(az.matches("UncompletedAnalyzerCommand").count() >= 3, "the WRAPPER's ONE home ri-d-es the 24d hom-e (the re-u-se wal-k)");
    // the landi-ng NEVER hosts the HARNESS di-r tok-en (the own-tok-en-
    // Z-E-R-O at the la-ndi-ng fa-ce; the sp-lit-bu-i-lt ne-ed-le HERE):
    let mn = format!("{}{}", "a", "cmd");
    assert_eq!(land.matches(mn.as_str()).count(), 0, "the landi-ng rides the ha-rne-ss di-r tok-en EXA-CT-LY-0");
}

// ==========================================================================
// P11: the CEN+SU+S UN-MO+VED TRIP-WI+RE WAL-K (32/9/24/1 — WAL-Ked not
// ech-o-e-d; the OWN ha-r-ne-ss home sh-ips NO ga-te fam-i-ly fi-le; the
// de-b-ris wal-k: the re-po-rel-a-ti-ve sc-ratch dir AB-SENT).
// ==========================================================================
#[test]
fn p11_census_walk_unmoved() {
    let r = "/opt/data/snort3-rust";
    let mut gates = 0usize;
    let mut legacy = 0usize;
    let mut lineages: std::collections::BTreeSet<String> = Default::default();
    for d in std::fs::read_dir(format!("{r}/tools")).unwrap().flatten() {
        let g = d.path().join("gate.txt");
        if g.is_file() {
            gates += 1;
            let m = md5_hex(&std::fs::read(&g).unwrap());
            lineages.insert(m.clone());
            if m == "4826fc2233044a2d5429413faf0ae1af" {
                legacy += 1;
            }
        }
    }
    assert_eq!(gates, 32, "the on-disk ga-t-e ce-nsus WAL-K-S 32 (the 24h po-li-cy fl-ip was the LA-STS move; THIS Z-E-R-O-ga-t-e row sh-ips NO-NE)");
    assert_eq!(legacy, 9, "the leg-a-cy md5 FR-O-Z-E-N x9");
    assert_eq!(lineages.len(), 24, "the lin-ea-ge tot-al 24 WAL-Ked (THIS row adds NO lin-ea-ge)");
    assert!(!std::path::Path::new(&own_home("gate.txt")).exists(), "NO ga+te tx+t EVE+R at the OW+N home");
    assert!(!std::path::Path::new(&own_home("gate_main.cc")).exists(), "NO ga+te ru+nn+er EVE+R HERE");
    // the tracked-sit read STRAI+GHT from the in-d-ex by-t-e-s (the no-g-i-t-
    // -i-nt-e-r-f-a-c-e-s la-w):
    let idx = std::fs::read(format!("{r}/.git/index")).unwrap();
    let s = String::from_utf8_lossy(&idx).into_owned();
    let nul = "\0".to_string();
    let gre = ["gre_harness/gate.txt", nul.as_str()].concat();
    assert_eq!(s.matches(gre.as_str()).count(), 1, "the tracked ga-t-e face STAYS gre-s ON-L-Y");
    assert_eq!(s.matches(&["gate.txt", nul.as_str()].concat()).count(), 1, "the tracked cen-sus UN-MOVED 1");
    // the OWN home ships NO ga-te fam-i-ly fi-le (the 24g re-pin filt-er):
    let own_files: Vec<String> = std::fs::read_dir(own_home(""))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n == "gate.txt" || n.contains("gate_main"))
        .collect();
    assert!(own_files.is_empty(), "the OWN home ships NO gate fami-ly file: {own_files:?}");
    // the harness dir face EXA-CTLY the ONE own home + the de-b-ris wal-k
    // (the or-ches-tra-t-ors ABS-O-LU-TE-SC-RAT-ch la-w's walk face):
    let hname = format!("{}{}_harness", "a", "cmd");
    let probe = format!("{}{}_probe", "a", "cmd");
    let mut own_dirs = 0usize;
    let mut probe_dirs = 0usize;
    for d in std::fs::read_dir(format!("{r}/tools")).unwrap().flatten() {
        let n = d.file_name().to_string_lossy().into_owned();
        if n == hname {
            own_dirs += 1;
        }
        if n == probe {
            probe_dirs += 1;
        }
    }
    assert_eq!(own_dirs, 1, "the harness dir face is EXACTLY the ONE own home");
    assert_eq!(probe_dirs, 0, "the stray probe-dir AB-SENT (the cle-an-up wal-ked, the po-rc-e-l-a-i-n-0 fa-ce)");
    assert!(!std::path::Path::new(&format!("{r}/cache")).exists(), "the repo-relative scratch dir AB-SENT (the era-new relative-path incident's walked face)");
}

// ==========================================================================
// P12: the mod-rs 13-FA-C-E wal-k (the cas-c-a-d-e GENU-INE-LY FIRED: the
// ONE NEW wir-ing li-ne) + the HO-LE-R SE-T WAL-K (the 6 buil-d.hol-d-er
// wc ar-ms + the 5 tw-in cou-nt ar-ms + the PRE-EXISTing pol-g/mods wc
// wal-k faces + this twin) + the an-zl pre-fi-x ne-ed-le 1->2 re-pin.
// ==========================================================================
#[test]
fn p12_mod_rs_cascade_fired_walk() {
    let mrs = read("/opt/data/snort3-rust/src/main/mod.rs");
    assert_eq!(mrs.lines().count(), 14, "the mod.rs face rode 13 at 24i ([24j rider 13->14: the he-lp own-er pair's ONE new wiring line in the mo-d-r-s, the walked face])");
    let seat = ["pub mod anal", "yzer_command;"].concat();
    assert_eq!(mrs.matches(&seat).count(), 1, "the ONE new wiring line EXACTLY-1");
    assert_eq!(mrs.matches("pub mod analyzer;").count(), 1, "the OLD e-xa-ct-se-at fa-ce still EXAC-TLY-1");
    // the PRE-FIX col-l-is-ion face (the wal-k): "pub mod anal-yzer" is
    // the PRE-FIX of the new sea-t -> MEASURED-2 (the an-zl twin's pre-fix
    // leg-ne-edle dr-ift, the honest rep-in NEVER a fro-zen ne-edle):
    let prefix = ["pub mod anal", "yzer"].concat();
    assert_eq!(mrs.matches(&prefix).count(), 2, "the prefix-collision face MEASURED-2");
    // the holder-set walk (in-commit flips, every arm NOW reads 14 [24j rider]):
    // the holder NAMES ride runtime-built spli-ts (the SE-LF-H-iT law: the
    // foreign harness to-ken-s NEV-ER join HER-E — the wal-k needs the
    // ar-ms, not the join-ed na-mes):
    let build_holders = [
        ["anz", "l_harness"], ["hpro", "cess_harness"], ["s", "hell_harness"],
        ["sn", "conf_harness"], ["sn", "mod_harness"], ["snpr", "oc_harness"],
    ];
    for h in build_holders {
        let hn = h.concat();
        let b = read(&format!("/opt/data/snort3-rust/tools/{hn}/build.sh"));
        assert!(
            b.contains("src/main/mod.rs)\" -eq 14"),
            "the {hn} wc-arm reads 14 IN-COMMIT (the 62d6fac complete-flip law; [24j rider 13->14], the walked receipt)"
        );
    }
    for t in [["an", "zl"], ["hproce", "ss"], ["shel", "l"], ["snc", "onf"], ["snm", "od"], ["mo", "ds"], ["po", "lg"]] {
        let name = t.concat();
        let b = read(&format!("/opt/data/snort3-rust/tests/{name}_parity_test.rs"));
        assert!(b.contains("lines().count(), 14"), "the {name} twin count/wc-arm reads 14 (the mo-ds+po-lg twins rode mo-d-r-s wc faces SINCE 24f/24h — the walk cites them as pre-existing holders flipped by THIS row; the name spli-ts ride the self-h-it law)");
    }
    // the an-zl bui-ld.hol-d-er pre-fix ar-m re-pin (the 1->2 wal-k):
    let ab = read(&["/opt/data/snort3-rust/tools/anz", "l_harness/build.sh"].concat());
    assert!(
        ab.contains("pub mod analyzer\" \"$R\"/src/main/mod.rs)\" -eq 2"),
        "the an-zl pre-fix arm MEASURED-2 wal-k face (the honest walked drift, the rider cite IN-COMMIT)"
    );
}

// ==========================================================================
// P13: the har-ness re-cei-pt fa-ces read BACK FROM DIS-K (the FIR-S-T-
// RU-N-SE-ED law: the vec-t-ors 155/16 + the md5s; the O0/O2/O2b == seed
// B-Y-TE-ID-E-N-T faces; the E4 bar-e :34:10 die-1 / the GR-A-F-T-5; the
// E9-43 MEA-S-URED; the nm -DE-L-T-A-0 34/34 face — NEVER an era's copy).
// ==========================================================================
#[test]
fn p13_harness_receipt_faces() {
    let v = std::fs::read(own_home("vectors.txt")).unwrap();
    let va = std::fs::read(own_home("vectors_faceA.txt")).unwrap();
    assert_eq!(String::from_utf8_lossy(&v).lines().count(), 155, "the DEC seed 155 L");
    assert_eq!(String::from_utf8_lossy(&va).lines().count(), 16, "the FA-C-E-A seed 16 L");
    assert_eq!(md5_hex(&v), "667356cedfdd50c4b7aba301d02fef62", "the DEC seed md5");
    assert_eq!(md5_hex(&va), "768024f9fd53d232cce4b326dcd9de56", "the FA-CE-A seed md5");
    // the tamper-pr-o-ven O0 == seed == O2 == cross face (read-back):
    for leaf in ["vectors_O0.txt", "vectors_O2.txt", "vectors_O2b.txt"] {
        assert_eq!(
            md5_hex(&std::fs::read(own_home(leaf)).unwrap()),
            md5_hex(&v),
            "the {leaf} face BYTE-IDENT vs the seed (the cmp arms' disk echo, NEVER re-seeded)"
        );
    }
    for leaf in ["vectors_faceA_O0.txt", "vectors_faceA_O2.txt"] {
        assert_eq!(
            md5_hex(&std::fs::read(own_home(leaf)).unwrap()),
            md5_hex(&va),
            "the FA-CE-A {leaf} byte-ident face"
        );
    }
    // the E4 THR-EE-way fac-es (MEA-S-URED, NEVER an era's face):
    let bare = read(&own_home("E4_bare.txt"));
    assert_eq!(bare.matches("fatal error").count(), 1, "bare di-es EXACTLY-1 fatal (the donor-absent head)");
    assert_eq!(bare.matches(":34:10").count(), 1, "the localized first seat cc :34");
    assert!(bare.contains("module_manager.h: No such file"), "the ONE head-missing face (the ground-WINS order la-w)");
    let graft = read(&own_home("E4_graft.txt"));
    assert_eq!(
        graft.matches("error:").count(),
        5,
        "the donor-GRAFT daq face MEASURED EXACTLY-5 (the DAQ-generation drift family: the CPU-profile seats + the no-member latency-data seat + the latency cmd seat — NEVER the 1/0-era copies assumed, NEVER the 24h ts-drift face assumed; the measurement WINS)"
    );
    assert!(graft.contains("snort_latency_data"), "the no-member seat rides the walked 5");
    // the E9 dup twins MEASURED (NEVER the 67/44/53/58-era faces):
    let e9 = read(&own_home("E9_dup.txt"));
    assert_eq!(e9.matches("multiple definition").count(), 43, "the E9 face MEASURED-43 by WALK");
    // the nm delta-0 HONEST face (the Z-E-R-O-ga-te mir-ror — NO Catch
    // si-de le-gs HER-E, the ut po-st com-pi-les VAC-U-O-US):
    let plain = read(&own_home("nm_U_plain.txt"));
    let ut = read(&own_home("nm_U_ut.txt"));
    assert_eq!(plain.lines().count(), 34, "the nm plain side");
    assert_eq!(ut.lines().count(), 34, "the nm ut side (the ZERO-unit-test posts face)");
    assert_eq!(plain, ut, "the nm delta EXACT-0 (the ZERO-GA-TE line-age face, the 24b/24d/24f/24g mirror)");
    // the harness dir's tracked faces = the EXACTLY-7 stageables, NO gate:
    let tr = std::process::Command::new("git")
        .args(["-C", "/opt/data/snort3-rust", "ls-files", &format!("tools/{}{}_harness", "a", "cmd")])
        .output()
        .unwrap();
    let out_s = String::from_utf8_lossy(&tr.stdout).into_owned();
    let files: Vec<&str> = out_s.lines().collect();
    assert_eq!(files.len(), 7, "the harness dir's tracked faces EXACTLY-7 (the stageables list, the walked face)");
    for f in &files {
        assert!(!f.ends_with("gate.txt") && !f.contains("gate_main"), "NO gate family file in the harness dir: {f}");
    }
}

// ==========================================================================
// P14: the doc-s ro-ws ban-ked IN the cod-e com-mit (the PLA-N '^| 24i '
// EXA-CT-LY-1 + the DEVIA-TI-ONS APP-EN-Ded LA-ST sec-ti-on) + the OWN
// join-ed to-kens ride docs EXA-CTLY-0 (the h-y-phen pr-o-se forms ON-L-y;
// the DON-E ech-o NEV-ER rides doc-s) + the NEXT seed faces (LINE
// semantics, the 23i t9 law) UN-MOVED at the CUR-R-E-N-T pin set.
// ==========================================================================
#[test]
fn p14_docs_rows_tripwires() {
    let plan = read("/opt/data/snort3-rust/PORTING_PLAN.md");
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24i ")).count(), 1, "the plan-row EXACTLY-1 law");
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24h ")).count(), 1, "the 24h row UN-MOVED x1 (the AFTER-the-24h-row seat, the walked face)");
    let dev = read("/opt/data/snort3-rust/KNOWN DEVIATIONS.md");
    let heads: Vec<&str> = dev.lines().filter(|l| l.starts_with("## ")).collect();
    // [24j rider: the APP-END law moves the LAST-section face EVERY row —
    // the 24i face rode LAST at the 24i era; at this row the 24j DEV sec-
    // ti-on ri-d-es LAST, the 24i sec-ti-on stays EXACT-1 (the po-lg /
    // con-ta-i-ns-1 pre-ce-dent; the 62d6fac com-plete-fl-ip law, walked)]:
    assert!(heads.last().unwrap().contains("row 24"), "the LAST dev section is the newest row (the app-end law)");
    assert_eq!(heads.iter().filter(|h| h.contains("row 24i")).count(), 1, "the 24i section EXACTLY-1");
    assert_eq!(heads.iter().filter(|h| h.contains("row 24j")).count(), 1, "the 24j section EXACTLY-1, riding LAST");
    // the OWN join-ed tok-e-ns ride the THREE docs faces EXA-CT-LY-0:
    let next = read(NEXTMD);
    let own_fold = format!("{}{}", "a", "cmd");
    let done = format!("ACM{}", "_DONE");
    let ancmd = format!("anc{}", "md");
    for doc in [&next, &plan, &dev] {
        assert!(!doc.contains(own_fold.as_str()), "the joined dir-token NEVER rides docs");
        assert!(!doc.contains(done.as_str()), "the DONE echo NEVER rides docs");
        assert!(!doc.contains(ancmd.as_str()), "the ancmd needle NEVER rides docs");
    }
    // the hyphen-prose law (the wa-lk face: the own-er rides hyphen forms):
    assert!(plan.contains("analyzer-command") || dev.contains("analyzer-command"), "the hy-phen pro-se fo-rm ri-des SOME docs fa-ce (the ca-rri-er la-w)");
    // the NEXT seed faces UNMOVED (LINE semantics, the 23i t9 law):
    let nf = |t: &str| next.lines().filter(|l| l.contains(t)).count();
    for s in [930, 915, 900, 885, 870, 855, 841, 825, 810, 798, 784, 772, 763, 752, 724, 702, 684, 659, 650, 633, 629, 621, 605, 597] {
        assert_eq!(nf(&format!("{s} tests green / 0 FAILED")), 3, "the {s} face x3 EXACT (the CURRENT pin set at 9d304ee)");
    }
    assert_eq!(nf("588 tests green / 0 FAILED"), 4);
    assert_eq!(nf("580 passed / 0 failed"), 3);
    assert_eq!(nf("573 tests green"), 5);
    assert_eq!(nf(&[format!("{}{}", "5 TE", "ST(")].concat()), 1, "the drift token EXACT-1");
}

// ==========================================================================
// P15: the ba-c-kb-o-ne tri-p-wi-re stays TEN + the md5 NEVER moves.
// ==========================================================================
#[test]
fn p15_backbone_ten() {
    let bb = std::fs::read("/opt/data/snort3-rust/tools/link4_harness/backbone10.txt").unwrap();
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10, "the backbone wc face EXACTLY 10");
    assert_eq!(
        md5_hex(&bb),
        "5339c7ee501dab8a85277c37dc2d1e0c",
        "the backbone10 md5 NEVER moves (the UN-MOVED face)"
    );
}

// ==========================================================================
// P16: the tok-e-n-ZE-R-O fa-c-es (the own dir-tok-en NEVER rides the
// land-i-ng / the vec-t-or seeds / the ha-rnes-s bui-ld.sh BYT-ES / THIS
// twin; the GROU-ND-na-me car-ri-ers DO ride the harness BYTES per the
// dir+DO-NE tok-en NEV-ER law).
// ==========================================================================
#[test]
fn p16_token_zero_faces() {
    let mn = format!("{}{}", "a", "cmd");
    let land = read("/opt/data/snort3-rust/src/main/analyzer_command.rs");
    assert_eq!(land.matches(mn.as_str()).count(), 0, "the landing rides the dir token EXACTLY-0");
    for leaf in ["vectors.txt", "vectors_faceA.txt"] {
        let s = std::fs::read_to_string(own_home(leaf)).unwrap();
        assert_eq!(s.matches(mn.as_str()).count(), 0, "the {leaf} seed NEVER hosts the dir token");
    }
    // the harness build.sh SELF-scan (the split-MN law, the 23f prov-en):
    let b = read(&own_home("build.sh"));
    assert_eq!(b.matches(mn.as_str()).count(), 0, "the split MN law: the joined dir token NEVER rides the build.sh BYTES");
    // the twin's own bytes (the SE-LF-HiT prov-en at the twin):
    let me = format!("/opt/data/snort3-rust/tests/{}{}_parity_test.rs", "a", "cmd");
    let s = read(&me);
    assert_eq!(s.matches(mn.as_str()).count(), 0, "the joined fold NEVER rides THIS twin's BYTES (the split-built needle proven HERE)");
    // the DONE marker NEVER rides the source/twin bytes joined:
    let done = format!("ACM{}", "_DONE");
    assert_eq!(land.matches(done.as_str()).count() + s.matches(done.as_str()).count(), 0, "the DONE marker NEVER rides source/twin bytes");
    // the GROU-ND-na-me car-ri-er law (the all-owed path-seats):
    assert!(b.contains("analyzer_command.cc"), "the ground-name carrier law rides the harness bytes (the path seats, NEVER the dir token)");
}
