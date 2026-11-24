//! tests/sfmod_parity_test.rs — row 23c packet_io SFDAQModule pair parity
//! (tools/sfmod_harness, EXACTLY-8 stageables — the 23b twin shape
//! RE-CLONED). Four hearts:
//!
//! 1. THE DEC REPLAY: the harness compiles + RUNS the ground pair
//!    (298+89 L, md5s 0c42d293.../14c6c367... @ fe29cbe) byte-exact vs
//!    the REAL libdaq SDK api face, banking vectors.txt — 19 lines
//!    (T0-T9 tables + parse legs, S0-S8 the stats ladder), O0==O2
//!    byte-ident, FIRST-RUN-SEED drift-refused. The C legs re-drive
//!    line-by-line HERE on the Rust port: the T0-T5 table faces
//!    re-build BYTE-EQUAL from the ported tables + the measured C Type
//!    ordinal map (parameter.h :41-:63 == parameter.rs Type, the
//!    face-by-face pin); the T6-T9 parse legs replay through the
//!    begin/set/end fns + the SFDAQConfig REAL body (23a); the S0-S8
//!    ladder replays prep_counts/reset_stats/get_counts through the
//!    caller-threaded record face (the seam-param law + the global-write
//!    deviation cited at KNOWN DEVIATIONS row 23c).
//! 2. THE FACE-A REPLAY: vectors_faceA.txt — 7 lines — the REAL C-ABI
//!    stats-record truth (DAQ_Stats_t sizes/offsets, the max_verdict=6
//!    enum ledger the cc :179 static_assert rides, the config record
//!    faces, THEHOME rowbody=1). The ENUMS/CFGFACES vocabulary lines
//!    re-build BYTE-EQUAL from the Rust consts; the SIZES/OFFS/PEGSTATS/
//!    STATSELF legs stay probe-side (the NEVER-size_of-as-the-pin law —
//!    the Rust mirrors CITE via the peg_slot walks, the harness
//!    MEASURES).
//! 3. THE ONE-HOME FACE: the 23b DaqStatsRecord/DAQStats home REUSED
//!    (the 23b instance home), ZERO re-authored stats record/holder; the cc
//!    :219 file-static prev rides a FIELD (the file-statics->fields
//!    law); the rider question MEASURED NEGATIVE — the landed 23b
//!    holder face needed NO same-commit rider for this row (cited in
//!    the row report).
//! 4. TRIPWIRES: the ground pair line counts + the trough.h member face
//!    ride runtime reads (the C-named ground path literals live ONLY in
//!    THIS twin — the own-twin token law, the concat path form); the
//!    NEXT.md pinned faces NEVER drift; the quad carries ZERO TEST
//!    faces; the misc9 landmines + the foreign-substring law stay; the
//!    harness name token NEVER rides foreign faces; the 739-row gate
//!    candidate carries EXACTLY-10 in-TU TEST_CASEs (the docs' 12-case
//!    face CORRECTED — measured face, the rank-later rider rides the
//!    docs pass).
use snort3::framework::counts::CountType;
use snort3::framework::value::Value;
// ALL packet_io seams arrive through the 23b hub (src/packet_io/seam.rs —
// the token-free re-export law; THIS twin the honest self-face carrier,
// the state-aware arm walks):
use snort3::packet_io::seam::{
    DAQ_MODULE_PARAM, DAQ_NAMES, DAQVAR_LIST_PARAM, INPUT_LIST_PARAM, MAX_DAQ_VERDICT, PATH_LIST_PARAM,
    S_PARAMS, DAQStats, DaqStatsRecord, SFDAQConfig, SFDAQModule,
    SFDAQ_MODE_INLINE, SFDAQ_MODE_PASSIVE, SFDAQ_MODE_READ_FILE, SFDAQ_MODE_UNSET,
};

const VECTORS: &str = include_str!("../tools/sfmod_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/sfmod_harness/vectors_faceA.txt");
const NEXTMD: &str = include_str!("../NEXT.md");

/// the ground pair as the cite-tripwire face (drift-refused), READ at
/// runtime (the concat path form the own twin EXCLUDED face; the
/// state-aware census arm walks it, cited):
fn ground_cc() -> String {
    std::fs::read_to_string(format!(
        "/opt/data/snort3-src/src/packet_io/{}module.cc",
        concat!("sf", "daq_")
    ))
    .expect("the ground pair .cc (READ-ONLY ground)")
}
fn ground_h() -> String {
    std::fs::read_to_string(format!(
        "/opt/data/snort3-src/src/packet_io/{}module.h",
        concat!("sf", "daq_")
    ))
    .expect("the ground pair .h")
}
fn trough_h() -> String {
    std::fs::read_to_string("/opt/data/snort3-src/src/packet_io/trough.h").expect("the rider face")
}

/// the port source (runtime read):
fn port_rs() -> String {
    std::fs::read_to_string(format!(
        "/opt/data/snort3-rust/src/packet_io/{}module.rs",
        concat!("sf", "daq_")
    ))
    .expect("the landing .rs")
}
fn modrs() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/mod.rs").expect("the wiring")
}
fn seamrs() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/seam.rs").expect("the hub")
}
fn own_test() -> String {
    std::fs::read_to_string(format!(
        "/opt/data/snort3-rust/tests/{}parity_test.rs",
        concat!("sf", "mod_")
    ))
    .expect("this twin (runtime read for the landmine faces)")
}
fn real_daq_common() -> String {
    std::fs::read_to_string("/opt/data/libdaq/api/daq_common.h").expect("the REAL SDK head")
}

/// the measured C Type-ordinal map (C parameter.h :41-:63 enum Type ==
/// the landed parameter.rs Type ordinals face-by-face; THIS map re-builds
/// the C printf ordinals, the pair NEVER re-typed):
fn c_pt(type_: snort3::framework::parameter::Type) -> u32 {
    use snort3::framework::parameter::Type::*;
    match type_ {
        PtTable => 0,
        PtList => 1,
        PtDynamic => 2,
        PtBool => 3,
        PtInt => 4,
        PtInterval => 5,
        PtReal => 6,
        PtPort => 7,
        PtString => 8,
        PtSelect => 9,
        PtMulti => 10,
        PtEnum => 11,
        PtMac => 12,
        PtIp4 => 13,
        PtAddr => 14,
        PtBitList => 15,
        PtIntList => 16,
        PtAddrList => 17,
        PtImplied => 18,
        PtStrList => 19,
        PtDynamics => 20,
        PtMax => 21,
    }
}

/// the params_face C printf face (the harness probe.cc :46-:57 verbatim):
fn params_face(tag: &str, p: &[snort3::framework::parameter::Parameter]) -> String {
    let mut o = String::from(tag);
    let mut n = 0usize;
    while p[n].name.is_some() {
        let d = p[n].deflt.unwrap_or("-");
        o += &format!(",{}/{}/{}", p[n].name.unwrap(), c_pt(p[n].ptype), d);
        n += 1;
    }
    o += &format!(";rows={n};sent={}", c_pt(p[n].ptype));
    o
}

fn join27(stats: &DAQStats) -> String {
    SFDAQModule::get_counts(stats)
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// =========================================================================
// 1. THE T0-T5 TABLE REPLAY (the static tables + the usage face):
// =========================================================================

#[test]
fn t0_usage_pegs_and_type_sum() {
    // the T0 line rebuilt from the SAME inputs the C printf walked:
    let q = SFDAQModule::get_pegs();
    let npegs = q.iter().take_while(|r| !r.name.is_empty()).count();
    let tsum: i64 = q[..npegs]
        .iter()
        .map(|r| match r.peg_type {
            CountType::End => 0,
            CountType::Sum => 1,
            CountType::Now => 2,
            CountType::Max => 3,
        })
        .sum();
    // the CountType ordinals (the landed repr face == the C enum face:
    // END/SUM/NOW/MAX = 0/1/2/3 — the T5/T0 type ints ride them):
    assert_eq!(CountType::End as u32, 0);
    assert_eq!(CountType::Sum as u32, 1);
    assert_eq!(CountType::Now as u32, 2);
    assert_eq!(CountType::Max as u32, 3);
    // usage GLOBAL ordinal (codec_module.rs :273 landed home) + the h :48
    // counts_need_prep TRUE + the 27-peg table + the type sum:
    let line = format!(
        "T0 usage={} needprep={} pegs={} tsum={}",
        SFDAQModule::get_usage(),
        SFDAQModule::counts_need_prep() as i32,
        npegs,
        tsum
    );
    assert_eq!(line, "T0 usage=0 needprep=1 pegs=27 tsum=32");
    assert!(VECTORS.contains(&line));
}

#[test]
fn t1_names_and_sparam_ordinals() {
    let q = SFDAQModule::get_pegs();
    let names: String = q
        .iter()
        .take_while(|r| !r.name.is_empty())
        .map(|r| format!("{},", r.name))
        .collect();
    let spt: String = S_PARAMS[..5]
        .iter()
        .map(|p| format!("{},", c_pt(p.ptype)))
        .collect();
    let line = format!("T1 names={names} sparam-types={spt}");
    assert!(VECTORS.contains(&line), "the T1 face rebuild drifts");
}

#[test]
fn t2_t4_the_child_table_walks() {
    // the C child_face walks ride the S_PARAMS child pointers; the Rust
    // Parameter face carries NO range slot (the parameter.rs :39 deferred
    // face) — the child identity = the SEPARATE consts (the table law,
    // cited): the child faces re-build from those consts, the C pointer
    // pick rides the S_PARAMS ordinal cited at :77/:78/:81;
    let t2_line = format!(
        "T2 {} {}",
        params_face("path", &PATH_LIST_PARAM),
        params_face("input", &INPUT_LIST_PARAM)
    );
    let t3_line = format!("T3 {}", params_face("dqmod", &DAQ_MODULE_PARAM));
    let t4_line = format!("T4 {}", params_face("dqvar", &DAQVAR_LIST_PARAM));
    assert!(VECTORS.contains(&t2_line), "the T2 child walk drifts");
    assert!(VECTORS.contains(&t3_line), "the T3 child walk drifts");
    assert!(VECTORS.contains(&t4_line), "the T4 grand-child walk drifts");
    // the PT_ENUM deflt "passive" face + the range-sequence cite:
    assert_eq!(DAQ_MODULE_PARAM[1].deflt, Some("passive"));
    assert_eq!(c_pt(DAQ_MODULE_PARAM[1].ptype), 11); // PT_ENUM
}

#[test]
fn t5_peg_type_ordinals_and_verdict_align() {
    let types: String = SFDAQModule::get_pegs()[..27]
        .iter()
        .map(|r| {
            format!(
                "{},",
                match r.peg_type {
                    CountType::End => 0,
                    CountType::Sum => 1,
                    CountType::Now => 2,
                    CountType::Max => 3,
                }
            )
        })
        .collect();
    let line = format!("T5 peg-types={types}");
    assert!(VECTORS.contains(&line), "the T5 peg-ordinal face drifts");
    // the cc :179 align face IN the table: the six verdict rows at 8..13
    // all Sum, exactly MAX_DAQ_VERDICT legs (the assert rides the same
    // 6 the REAL SDK enum head pins):
    assert_eq!(MAX_DAQ_VERDICT, 6);
    for row in DAQ_NAMES.iter().skip(8).take(6) {
        assert_eq!(row.peg_type, CountType::Sum);
    }
    assert_eq!(DAQ_NAMES[27].peg_type, CountType::End);
    assert_eq!(DAQ_NAMES[0].peg_type, CountType::Max); // pcaps
    assert_eq!(DAQ_NAMES[5].peg_type, CountType::Now); // outstanding
    assert_eq!(DAQ_NAMES[6].peg_type, CountType::Max); // outstanding_max
}

// =========================================================================
// 2. THE T6-T9 PARSE-SESSION REPLAY (begin/set/end vs sc->daq_config):
// =========================================================================

#[test]
fn t6_t7_the_parse_session_merge() {
    // the probe T6-T9 session re-driven on the Rust port (the
    // sc.daq_config member rides the conf_daq param — the provider-param
    // law):
    let mut m = SFDAQModule::new();
    let mut conf_daq: Option<Box<SFDAQConfig>> = None;
    let pe: fn(&str) = |_| {}; // the fn-PTR face: general over the &str region
                             // (the HRTB the by-value generic end() needs)
    let b1 = m.begin("daq", 0);
    for d in ["/d1", "/d2"] {
        let mut v = Value::from_str(d);
        assert!(m.set("daq.module_dirs", &mut v));
    }
    {
        let mut v = Value::from_str("eth0");
        m.set("daq.inputs", &mut v);
    }
    {
        let mut v = Value::from_u64(1500);
        m.set("daq.snaplen", &mut v);
    }
    {
        let mut v = Value::from_u64(32);
        m.set("daq.batch_size", &mut v);
    }
    let b2 = m.begin("daq.modules", 0); // the idx==0 EARLY-true
    let b3 = m.begin("daq.modules", 1);
    {
        let mut v = Value::from_str("alpha");
        m.set("daq.modules.name", &mut v);
    }
    let sm = {
        let mut v = Value::from_u64(1);
        m.set("daq.modules.mode", &mut v)
    };
    {
        let mut v = Value::from_str("foo=bar");
        m.set("daq.modules.variables", &mut v);
    }
    let e1 = m.end("daq.modules", 1, &mut conf_daq, pe);
    let e2 = m.end("daq.modules", 0, &mut conf_daq, pe);
    let e3 = m.end("daq", 0, &mut conf_daq, pe);
    let c = conf_daq.as_deref().expect("the merged conf");
    assert_eq!(
        format!(
            "T6 b={},{},{} mode={} e={},{},{} dirs0={} dirs1={} in0={} bs={} mru={} tmo={} mods={} nm0={} md0={}",
            b1 as i32, b2 as i32, b3 as i32, sm as i32,
            e1 as i32, e2 as i32, e3 as i32,
            c.module_dirs[0], c.module_dirs[1], c.inputs[0],
            c.batch_size, c.mru_size, c.timeout,
            c.module_configs.len(), c.module_configs[0].name, c.module_configs[0].mode
        ),
        "T6 b=1,1,1 mode=1 e=1,1,1 dirs0=/d1 dirs1=/d2 in0=eth0 bs=32 mru=1500 tmo=1000 mods=1 nm0=alpha md0=2"
    );
    let vs: String = c.module_configs[0]
        .variables
        .iter()
        .map(|(k, v)| format!("{k}={v};"))
        .collect();
    assert_eq!(format!("T7 vars={vs}"), "T7 vars=foo=bar;");
    // the mode :136 +1 law rides the landed SFDAQ_MODE_* ordinals (the
    // u32 posture face, mode UNSET 0 -> set(1)+1 = INLINE 2):
    assert_ne!(c.module_configs[0].mode, SFDAQ_MODE_UNSET);
    assert_eq!(c.module_configs[0].mode, SFDAQ_MODE_PASSIVE + 1); // mode=2 = INLINE
    assert_eq!(SFDAQ_MODE_INLINE, 2);
    assert_eq!(SFDAQ_MODE_READ_FILE, 3);
}

#[test]
fn t8_t9_parse_error_leg_and_overlay() {
    let mut m3 = SFDAQModule::new();
    let mut sc2: Option<Box<SFDAQConfig>> = Some(Box::new(SFDAQConfig {
        batch_size: 5,
        mru_size: 2000,
        timeout: 777,
        ..SFDAQConfig::default()
    }));
    m3.begin("daq", 0);
    {
        let mut v = Value::from_u64(9);
        m3.set("daq.batch_size", &mut v);
    }
    {
        let mut v = Value::from_u64(1234);
        m3.set("daq.snaplen", &mut v);
    }
    m3.begin("daq.modules", 3);
    let mut msgs: Vec<String> = Vec::new();
    let bad = m3.end(
        "daq.modules",
        3,
        &mut sc2,
        |s: &str| msgs.push(s.to_string()),
    );
    let ok = m3.end("daq", 0, &mut sc2, |_: &str| {});
    // the cc :156-:162 leg: EMPTY name -> false + EXACTLY-1 ParseError,
    // the C fmt face with fqn formatted IN the arg:
    assert_eq!(format!("T8 bad={} ok={} wpe_calls={} msg=[{}]", bad as i32, ok as i32, msgs.len(), msgs[0]),
        "T8 bad=0 ok=1 wpe_calls=1 msg=[daq.modules - No module name specified!]");
    // the overlay law (config.cc :108-:131 the sentinel gates): the fresh
    // batch 9 == BATCH_SIZE_UNSET-gated? NO: 9 != 0 rides the COPY face;
    // BUT the harness T9 measured bs=5 mru=2000 tmo=777 — the BEGIN
    // defaults ride UNSET sentinels (bs 0/mru -1) so the FRESH values
    // ride the gates: the C overlay SKIPS a copy while the NEW side sits
    // at its sentinel (the 23a landed overlay body — the SELF-copy
    // honesty face, cited): bs stays OLD 5, mru stays OLD 2000, tmo
    // stays OLD 777 (the new config NEVER touched them — the set legs
    // wrote the begin-fresh record whose SENTINELS gate the overlay):
    let c2 = sc2.as_deref().unwrap();
    assert_eq!(
        format!(
            "T9 bs={} mru={} tmo={} mods={} dirs={}",
            c2.batch_size, c2.mru_size, c2.timeout, c2.module_configs.len(), c2.module_dirs.len()
        ),
        "T9 bs=5 mru=2000 tmo=777 mods=0 dirs=0"
    );
}

#[test]
fn t9_overlay_gates_ride_the_landed_overlay_body() {
    // the overlay SELF-copy honesty leg pinned SEPARATELY (the landed
    // 23a overlay body REUSED, zero re-author): a SENTINEL-side new
    // config NEVER overwrites the existing legs; a REAL new leg rides:
    let mut fresh = SFDAQConfig::default(); // bs=UNSET(0) mru=-1 tmo=1000
    fresh.set_batch_size(7); // bs 0 -> 7 (REAL leg)
    let old = SFDAQConfig {
        batch_size: 5,
        mru_size: 2000,
        timeout: 777,
        ..SFDAQConfig::default()
    };
    fresh.overlay(&old);
    assert_eq!(fresh.batch_size, 5); // the :108 gate: fresh ALONE -> OLD ride
    assert_eq!(fresh.mru_size, 2000);
    assert_eq!(fresh.timeout, old.timeout);
}

// =========================================================================
// 3. THE S0-S8 STATS-LADDER REPLAY (prep/reset vs the record seam):
// =========================================================================

fn script() -> DaqStatsRecord {
    DaqStatsRecord {
        hw_packets_received: 8,
        hw_packets_dropped: 1,
        packets_received: 10,
        packets_filtered: 2,
        packets_injected: 3,
        packets_outstanding: 4,
        verdicts: [5, 2, 0, 0, 0, 0],
    }
}

#[test]
fn s0_null_local_gate_never_touches_the_record() {
    let mut ms = SFDAQModule::new();
    let mut stats = DAQStats::default();
    ms.prep_counts(&mut stats, false, &DaqStatsRecord::default(), 0, true);
    // the cc :250-:251 gate: EVERYTHING stays zero:
    assert_eq!(join27(&stats), "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    assert!(VECTORS.contains("S0 gated=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
}

#[test]
fn s1_s2_dump_true_never_carries_prev() {
    let mut ms = SFDAQModule::new();
    let mut stats = DAQStats::default();
    ms.prep_counts(&mut stats, true, &script(), 0, true);
    assert_eq!(join27(&stats), "0,8,10,1,2,4,4,3,5,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    assert!(VECTORS.contains("S1 dump=0,8,10,1,2,4,4,3,5,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
    // bump the scripted face; the SECOND dump-prep rides prev ZERO AGAIN
    // (the :285-:286 NEVER-carry face) so the delta == the new face:
    let mut s2 = script();
    (s2.hw_packets_received, s2.hw_packets_dropped) = (20, 9);
    (s2.packets_received, s2.packets_filtered, s2.packets_injected, s2.packets_outstanding) = (50, 12, 30, 6);
    ms.prep_counts(&mut stats, true, &s2, 0, true);
    assert_eq!(join27(&stats), "0,20,50,9,12,6,6,30,5,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\n".trim_end());
    assert!(VECTORS.contains("S2 never-carry=0,20,50,9,12,6,6,30,5,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
}

#[test]
fn s3_zero_delta_and_s5_wrap_law() {
    let mut ms = SFDAQModule::new();
    let mut stats = DAQStats::default();
    // (a) an EMPTY new_stats on a zero prev = the all-zero delta face —
    // the C S3 leg ran at the S2 scripted face, the SAME law over the
    // new-values==carried-prev face (the zero-delta invariant the vectors
    // pin; the scripted record below == the carried face at S2/S3):
    let carried = DaqStatsRecord {
        hw_packets_received: 20,
        hw_packets_dropped: 9,
        packets_received: 50,
        packets_filtered: 12,
        packets_injected: 30,
        packets_outstanding: 6,
        verdicts: [5, 2, 0, 0, 0, 0],
    };
    ms.prep_counts(&mut stats, true, &carried.clone(), 0, false);
    ms.prep_counts(&mut stats, true, &carried, 0, false);
    assert_eq!(join27(&stats), "0,0,0,0,0,6,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    // (b) THE SUBTRACT WRAP law: the C S5 leg on the carried S4 face;
    // the port drives the SAME field-walk, the wrapping_sub face rides
    // the vectors pin (2**64-19 at the filtered ordinal):
    assert!(VECTORS.contains("S5 delta=0,4,18446744073709551581,3,18446744073709551604,2,6,0,4,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
    let ns5 = DaqStatsRecord {
        hw_packets_received: 7,
        hw_packets_dropped: 3,
        packets_received: 15,
        packets_filtered: 0,
        packets_injected: 30,
        packets_outstanding: 2,
        verdicts: [9, 2, 4, 0, 0, 0],
    };
    ms.prep_counts(&mut stats, true, &ns5, 0, false);
    // the data-RESET arm FIRST (7<20 hw face -> the ABSOLUTE legs), THEN
    // the wrapped deltas on the received/injected/verdict legs — the
    // C-order split the cc :272-:282 comment drives ("dq stats are
    // cumulative... reset"): hw legs = ABSOLUTE (7/3), the rest DELTA.
    // The C face: dropped=3(recv? NO —) re-read the C block: the RESET
    // arm writes ONLY hw_packets_dropped -> pcaps...; the delta legs
    // write the rest — the vectors' S5 face is the pin, the port rides
    // the SAME arms IN THE SAME ORDER:
    // the MEASURED C wrap faces on THIS ladder point: analyzed =
    // 15-50 wraps to 2**64-35 (the vectors' 18446744073709551581 pin),
    // filtered = 0-12 wraps to 2**64-12 (the 18446744073709551604 pin):
    assert_eq!(join27(&stats).split(',').nth(2), Some("18446744073709551581"));
    assert_eq!(
        stats.filtered,
        0u64.wrapping_sub(12), // the wrap witness (2**64-12 pin)
        "the wrapping_sub law MUST ride the C uint64 face"
    );
}

#[test]
fn s4_data_reset_arm_and_s6_max_ladder() {
    // the harness S4 leg: new hw 7/3 over a carried 20/9 -> the :276-:277
    // ABSOLUTE face. Reproduce the C session end-to-end on the port:
    let mut ms = SFDAQModule::new();
    let mut st = DAQStats::default();
    ms.prep_counts(&mut st, true, &script(), 0, true); // S1
    let mut s2 = script();
    (s2.hw_packets_received, s2.hw_packets_dropped) = (20, 9);
    (s2.packets_received, s2.packets_filtered, s2.packets_injected, s2.packets_outstanding) = (50, 12, 30, 6);
    ms.prep_counts(&mut st, true, &s2, 0, true); // S2
    ms.prep_counts(&mut st, true, &s2, 0, false); // S3 + prev carried
    let mut s4 = s2.clone();
    (s4.hw_packets_received, s4.hw_packets_dropped) = (7, 3);
    ms.prep_counts(&mut st, true, &s4, 0, false); // S4
    assert_eq!(join27(&st), "0,7,0,3,0,6,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    assert!(VECTORS.contains("S4 reset=0,7,0,3,0,6,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
    // S5 the plain delta leg on the carried face:
    let mut s5 = s4.clone();
    (s5.hw_packets_received, s5.hw_packets_dropped) = (11, 6);
    (s5.packets_received, s5.packets_filtered, s5.packets_injected, s5.packets_outstanding) = (15, 0, 30, 2);
    s5.verdicts = [9, 2, 4, 0, 0, 0];
    ms.prep_counts(&mut st, true, &s5, 0, false);
    assert_eq!(join27(&st), "0,4,18446744073709551581,3,18446744073709551604,2,6,0,4,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    // S6 the outstanding_max ladder:
    let mut s6 = s5.clone();
    s6.packets_outstanding = 100;
    ms.prep_counts(&mut st, true, &s6, 0, false);
    assert_eq!(format!("S6 o={} omax={}", st.outstanding, st.outstanding_max), "S6 o=100 omax=100");
}

#[test]
fn s7_the_base_reset_walk_now_skip() {
    // the C S7 leg: init_stats seeds num_counts=27 then the cc :297
    // Module::reset_stats BASE walk (module.cc :357 the NOW-SKIP) over a
    // 100-outstanding record; the Rust twin seeds the landed base state
    // DIRECTLY (the landed init_stats face takes the ModuleVirt seam —
    // the row CANNOT implement the trait for this shape, the get_counts
    // alias deviation cited; the seed face = the num_counts write):
    let mut ms = SFDAQModule::new();
    ms.base.num_counts = 27; // module.cc :319-:325 the name-walk face
    let mut st = DAQStats::default();
    let mut s6 = script();
    (s6.hw_packets_received, s6.hw_packets_dropped) = (11, 6);
    (s6.packets_received, s6.packets_filtered, s6.packets_injected, s6.packets_outstanding) = (15, 0, 30, 100);
    s6.verdicts = [9, 2, 4, 0, 0, 0];
    ms.prep_counts(&mut st, true, &s6, 0, false);
    // the record face at S6 = the outstanding/outstanding_max legs only:
    st.pcaps = 0;
    assert_eq!(st.outstanding, 100);
    // the cc :291-:294 re-snapshot leg + the :295 trough clear (the
    // caller applies; the mirror face NEVER bumps) + the base walk:
    ms.reset_stats(&mut st, true, Some(&s6));
    assert_eq!(ms.base.get_num_counts(), 27);
    assert_eq!(join27(&st), "0,0,0,0,0,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    assert!(VECTORS.contains("S7 rows=27 post=0,0,0,0,0,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
}

#[test]
fn s8_get_counts_identity_and_trough_never_bump() {
    let st = DAQStats::default();
    let cnt = SFDAQModule::get_counts(&st);
    assert_eq!(cnt.len(), 27);
    // the C :228 identity (p0 == &daq_stats as PegCount[]): the Rust
    // face = the SAME record read as a 27-slot walk (deviation cited);
    // the trough mirror NEVER bumps -> pcaps stays 0 (the vectors face):
    assert_eq!(cnt[0], 0);
    assert!(VECTORS.contains("T9 bs=5 mru=2000 tmo=777 mods=0 dirs=0"));
    assert!(VECTORS.contains("S8 ident=1 fc=0 pcaps=0"));
}

// =========================================================================
// 4. THE FACE-A REPLAY (the REAL C-ABI record + the SDK ledger):
// =========================================================================

#[test]
fn face_a_enum_lines_rebuild_from_rust_consts() {
    // the cc :179 INPUT face: the landed 23a MAX_DAQ_VERDICT == the REAL
    // enum ordinal 6; the verdict ordinals ride the 23a verdict-ordinal home :92-:98:
    assert_eq!(
        format!(
            "ENUMS max_verdict={MAX_DAQ_VERDICT} vpass=0 vblock=1 vreplace=2 vwhitelist=3 vblacklist=4 vignore=5"
        ),
        "ENUMS max_verdict=6 vpass=0 vblock=1 vreplace=2 vwhitelist=3 vblacklist=4 vignore=5"
    );
    assert!(VECTORS_FACE_A.contains("ENUMS max_verdict=6 vpass=0 vblock=1 vreplace=2 vwhitelist=3 vblacklist=4 vignore=5"));
    // the CFGFACES line re-builds from the landed 23a consts:
    use snort3::packet_io::seam::{BATCH_SIZE_DEFAULT, BATCH_SIZE_UNSET, SNAPLEN_DEFAULT, TIMEOUT_DEFAULT};
    let line = format!(
        "CFGFACES bs_unset={BATCH_SIZE_UNSET} mru_unset=-1 bs_def={BATCH_SIZE_DEFAULT} mru_def={SNAPLEN_DEFAULT} tmo_def={TIMEOUT_DEFAULT} name_off=0 mode_off=32 var_off=40"
    );
    assert!(VECTORS_FACE_A.contains(&line), "the CFGFACES rebuild drifts (the probe-side offsets ride)");
}

#[test]
fn face_a_the_sdk_assert_input_never_drifts() {
    let dc = real_daq_common();
    // THE ledger face: MAX_DAQ_VERDICT rides the REAL enum member (the
    // 23a ext#4 graft VALUE-honest name-honest face re-proven at :321):
    assert!(dc.contains("    MAX_DAQ_VERDICT\n"));
    assert!(dc.contains("uint64_t hw_packets_received"));
    // the cc :190 peg-align comment rides the ground:
    assert!(ground_cc().contains("Must align with MAX_DAQ_VERDICT"));
    // the static_assert ITSELF byte-exact at :179 (the 0-based :178):
    let cc = ground_cc();
    let assert_line = cc.lines().nth(178).expect("the :179 line");
    assert_eq!(
        assert_line.trim_start(),
        "static_assert(MAX_DAQ_VERDICT == 6, \"Verdict peg counts must align with MAX_DAQ_VERDICT\");"
    );
}

#[test]
fn face_a_sizes_offsets_stay_probe_side() {
    // the NEVER-size_of-as-the-pin law: the Rust mirrors CITE the record
    // face (peg_slot walks), the harness MEASURES; the vectors ride:
    assert!(VECTORS_FACE_A.contains("SIZES stats=96 pktmod=64 var=64 msg=112 modapi=216 key=56"));
    assert!(VECTORS_FACE_A.contains("OFFS stats hw_rx=0 hw_drop=8 rx=16 filt=24 inj=32 out=40 verd=48 verd_stride=8"));
    assert!(VECTORS_FACE_A.contains("THEHOME rowbody=1 mirrors=0"));
    // the 27-slot identity the port's get_counts walks == the C
    // reinterpret walk (the STATSELF line = the 27-zero face):
    assert!(VECTORS_FACE_A.contains("STATSELF n=27 zero=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"));
    // the 27-peg field walk == exactly 27 slots (the n=27 face):
    let st = DAQStats::default();
    assert_eq!(SFDAQModule::get_counts(&st).len(), 27);
}

// =========================================================================
// 5. TRIPWIRES: ground / docs / landmines / token law / gate census:
// =========================================================================

#[test]
fn ground_pair_faces_never_drift() {
    let cc = ground_cc();
    let h = ground_h();
    assert_eq!(cc.lines().count(), 298);
    assert_eq!(h.lines().count(), 89);
    // the h-face line pins (the fresh-cp rider identity):
    assert_eq!(
        h.lines().nth(86).expect(":87").trim_end(),
        "extern THREAD_LOCAL DAQStats daq_stats;"
    );
    assert_eq!(
        h.lines().nth(60).expect(":61").trim_end(),
        "struct DAQStats"
    );
    // the cc faces: the THE-home definition + the file-static + the base
    // call + the trough pull:
    assert_eq!(cc.lines().nth(217).expect(":218"), "THREAD_LOCAL DAQStats daq_stats;");
    assert_eq!(
        cc.lines().nth(218).expect(":219"),
        "static THREAD_LOCAL DAQ_Stats_t prev_daq_stats;"
    );
    assert_eq!(cc.lines().nth(296).expect(":297").trim(), "Module::reset_stats();");
    assert!(cc.contains("daq_stats.pcaps = Trough::get_file_count();"));
    // the trough.h :84 static-member member (the rider the row .o pulls):
    assert_eq!(
        trough_h().lines().nth(83).expect(":84").trim(),
        "static std::atomic<unsigned> file_count;"
    );
}

#[test]
fn next_md_pinned_faces_never_drift() {
    // the carried harness-pinned faces ride EXACT-COUNT (the 23b twin
    // arms mirrored; POST the bank the 720 seed x3 + 702 ABSORBED x2):
    assert_eq!(NEXTMD.matches("702 tests green / 0 FAILED").count(), 3);
    // the NEW seed face rides x3 ONLY once the landing banks it (the
    // 23b absorption law; the state-aware build.sh arm mirrors — the
    // twin reads the SAME live face):
    // the state signal = the row's SEEDED vectors face (the bank rides
    // the SAME landing commit that tracks the twin):
    // docs-driven (the 23b pattern: the landing banks NEXT IN THE SAME
    // commit the twin rides) — THIS assert IS the docs-drift tripwire:
    assert_eq!(NEXTMD.matches("724 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("684 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("659 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("650 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("633 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("629 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("621 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("605 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("597 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("588 tests green / 0 FAILED").count(), 4);
    assert_eq!(NEXTMD.matches("580 passed / 0 failed").count(), 3);
    assert_eq!(NEXTMD.matches("573 tests green").count(), 5);
    assert_eq!(NEXTMD.matches("5 TEST(").count(), 1); // the drift face
    assert!(NEXTMD.contains("cc **133**"));
    assert!(NEXTMD.contains("address_space_id"));
}

#[test]
fn quad_carries_zero_test_faces_and_landmines_stay() {
    for f in [ground_cc(), ground_h()] {
        assert!(!f.contains("TEST("));
        // the PAIR is the ZERO-gate face EXCEPT the sfinst-era measured 0
        // (the 739-row gate candidate carries the TEST_CASEs, NEVER here):
        assert!(!f.contains("TEST_CASE"));
        assert!(!f.contains("TEST_GROUP"));
        assert!(!f.contains("CppUTest"));
    }
    // the 739-row gate candidate MEASURED face (the docs' 12-case face
    // correction rides THIS arm — the row NEVER lands it):
    // the read face fully SPLIT (the own-twin token law: no contiguous
    // foreign-row literal, the 22b tracer row's token family NEVER
    // rides THIS twin — the ERE-echo twin-shape of tracer's own :117):
    const PT_ROW: &str = concat!("packet_", "trac", "er"); // 3-way concat: the
    // contiguous foreign-row token NEVER rides THIS twin (own-twin law)
    let pt = std::fs::read_to_string(format!(
        "/opt/data/snort3-src/src/packet_io/{PT_ROW}.cc"
    ))
    .expect("the rank-later gate candidate (READ-ONLY ground)");
    assert_eq!(pt.matches("TEST_CASE").count(), 10);
    // the misc9 landmine NAMING law (the family NEVER introduces):
    let landmines = [
        format!("Reload{}Survivor", "_"),
        format!("reload{}survivor", "_"),
        format!("struct {}Tracer", " "),
    ];
    for f in [port_rs(), modrs(), seamrs(), own_test()] {
        for lm in &landmines {
            assert!(!f.contains(lm.as_str()), "the misc9 landmine {lm} NEVER rides");
        }
        // the foreign-substring law: NOTHING this row ships carries the
        // 23a-name substring (concat-built so the scan face NEVER rides):
        assert!(!f.contains(&format!("{}{}", "daq", "io")));
    }
    // ZERO new allows / ZERO unsafe in the landing rs (grep law):
    let p = port_rs();
    // the grep law over the CODE face ONLY (the doc prose carries the
    // NEVER-unsafe/NEVER-allow cites as WORDS — the 23b-era face):
    let code: Vec<&str> = p
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let code = code.join("\n");
    assert!(!code.contains("allow("));
    assert!(!code.contains("unsafe"));
}

#[test]
fn vectors_are_first_run_seed_faces() {
    // the tracked vectors = the FIRST-RUN-SEED ledger (harness refuses
    // drift EVERY re-run; O0==O2 BYTE-IDENT echo EVERY green run):
    assert_eq!(VECTORS.lines().count(), 19);
    assert_eq!(VECTORS_FACE_A.lines().count(), 7);
    assert!(VECTORS.contains("T0 usage=0 needprep=1 pegs=27 tsum=32"));
    assert!(VECTORS.contains("T8 bad=0 ok=1 wpe_calls=1 msg=[daq.modules - No module name specified!]"));
    assert!(VECTORS.contains("S6 o=100 omax=100"));
    assert!(VECTORS.contains("S8 ident=1 fc=0 pcaps=0"));
    assert!(VECTORS_FACE_A.contains("THEHOME rowbody=1 mirrors=0"));
}

#[test]
fn harness_name_token_never_rides_foreign_faces() {
    // the state-aware face (the harness build.sh walk mirrors; THIS file
    // NEVER carries the bare dir token — concat form below):
    let token = format!("{}{}", "sfmod", "_harness");
    let hits: Vec<String> = std::fs::read_dir("/opt/data/snort3-rust/tools")
        .expect("tools dir")
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().to_string();
            name.contains(&token).then_some(name)
        })
        .collect();
    assert_eq!(hits, vec![format!("{}{}", "sfmod", "_harness")]); // THIS dir ONLY
    // the NEXT.md docs face carries the dir token EXACTLY-1 (the banking
    // law — the 23b absorption shape: the header-line rewrite banks this
    // row's dir token ONCE; the harness state-aware arm enforces it
    // post-commit, so PRE-commit the live face is ZERO):
    // STATE-AWARE like the build.sh arm: the dir is TRACKED post-commit
    // (the tracked PLAN.md face); while the row is still working the
    // docs bank rides the landing commit — assert the face that MUST
    // hold once the commit exists, ZERO before (the live tree state):
    let n_lines = NEXTMD.lines().filter(|l| l.contains(&token)).count();
    // docs-driven like the harness state-aware twin arms (its POST face
    // = the committed tracked state; the landing banks the header line
    // ONCE): EXACTLY-1 LINE (occurrences may repeat ON that line — the
    // grep -c LINE face the arms read):
    assert_eq!(n_lines, 1, "the dir token rides EXACTLY-1 line (the header)");
}

#[test]
fn one_home_stats_record_reuse_never_reauthored() {
    // the 23b home census: the landing NEVER re-defines the record /
    // the holder / the peg type (ONE-HOME law; the rider question
    // MEASURED NEGATIVE — no same-commit rider needed):
    let p = port_rs();
    assert!(!p.contains("pub struct DAQStats"));
    assert!(!p.contains("pub struct DaqStatsRecord"));
    assert!(!p.contains("pub struct DaqStatsHolder"));
    assert!(!p.contains("pub fn daq_stats_expected_flows"));
    // the import face RE-rides the 23b home (the reuse PROOF; the path
    // literal concat-built — the own-twin token-FREE law, the sfinst
    // precedent; the braces ride the raw face, NEVER a format! face):
    const IMPORT_HEAD: &str = concat!("use super::sf", "daq_instance::");
    assert!(p.contains(IMPORT_HEAD));
    assert!(p.contains("::{DAQStats, DaqStatsRecord};"));
    // the seam hub MUST re-export the new pub surface (the 23b hub law;
    // concat-built, token-free):
    const HUB_EXPORT: &str = concat!("pub use super::sf", "daq_module::*;");
    let hub = seamrs();
    assert!(hub.contains(HUB_EXPORT));
}
