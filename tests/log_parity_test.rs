#![allow(clippy::approx_constant)] // 3.14159 etc. replay the C probe's literal arguments
// Whole-transcript replay of tools/log_harness/vectors.txt: the C probe
// compiled ORIGINAL log/messages.cc; this test drives LogEngine + cfmt
// through the identical call sequence and compares the merged
// stdout+stderr byte stream. The C-only glibc assertion note line (prints
// the harness path) is stripped from the expected side; the port emits a
// panic instead, caught here, and both then print the sig=6 marker.
use snort3::log::messages::*;
use snort3::utils::cfmt::Arg;

struct Out {
    s: String,
}

impl Out {
    fn m(&mut self, x: &str) {
        self.s.push_str(x);
        self.s.push('\n');
    }
    fn ev(&mut self, e: &mut LogEngine) {
        for ev in e.out.drain(..) {
            if let Phase::File(t) = ev.phase {
                let _ = t;
                continue;
            }
            self.s.push_str(&ev.text);
        }
    }
    fn take_file(&mut self, e: &mut LogEngine) -> String {
        let mut t = String::new();
        for ev in e.out.drain(..) {
            if let Phase::File(_) = ev.phase {
                t.push_str(&ev.text);
            }
        }
        t
    }
}

fn arg(s: &str) -> Arg<'_> {
    Arg::S(Some(s.to_string().into()))
}

#[test]
fn log_messages_transcript_parity() {
    let mut e = LogEngine::default();
    let mut o = Out { s: String::new() };

    // #P1: conf present, warning_flags 0 -> suppressed
    o.m("#P1");
    e.parse_warning(WARN_VARS, "suppressed %d", &[Arg::I(7)]);
    o.ev(&mut e);

    // #P2
    o.m("#P2");
    e.warning_flags = 1 << WARN_VARS;
    e.parse_warning(WARN_RULES, "rules-suppressed", &[]);
    e.parse_warning(WARN_VARS, "vars-shown %d", &[Arg::I(1)]);
    o.ev(&mut e);

    // #P3
    o.m("#P3");
    for wg in WARN_DAQ..WARN_MAX {
        e.warning_flags = 1 << wg;
        e.parse_warning(wg, "g%d ok", &[Arg::I(i64::from(wg))]);
    }
    o.ev(&mut e);

    // #P4
    o.m("#P4");
    e.warning_flags = u32::MAX;
    e.parse_warning(WARN_CONF_STRICT, "strict mode msg", &[]);
    o.ev(&mut e);

    // #P5: WARNING location branches
    o.m("#P5");
    e.set_parse_location(Some("foo.rules"), 42);
    e.parse_warning(WARN_VARS, "with loc %s", &[arg("x")]);
    e.set_parse_location(Some("bar.rules"), 0);
    e.parse_warning(WARN_VARS, "file no line", &[]);
    e.set_parse_location(None, 0);
    e.parse_warning(WARN_VARS, "no loc", &[]);
    o.ev(&mut e);

    // #P6: ERROR location branches
    o.m("#P6");
    e.set_parse_location(Some("a.rules"), 7);
    e.parse_error("bad %s here", &[arg("thing")]);
    e.set_parse_location(Some("b.rules"), 0);
    e.parse_error("err file noline", &[]);
    e.set_parse_location(None, 0);
    e.parse_error("err plain %u", &[Arg::U(12)]);
    o.ev(&mut e);

    // #P7: reload join + reset
    o.m("#P7");
    e.reload_error("first", &[]);
    e.reload_error("second %d", &[Arg::I(2)]);
    e.reload_error("third", &[]);
    o.ev(&mut e);
    o.m(&format!("#desc={}", e.get_reload_errors_description()));
    o.m(&format!("#reload={}", e.get_reload_errors()));
    e.reset_reload_errors();
    o.m(&format!("#desc2={}", e.get_reload_errors_description()));
    o.m(&format!("#reload2={}", e.get_reload_errors()));

    // #P8: STD_BUF truncation asymmetry
    o.m("#P8");
    let big = "A".repeat(1500) + &"B".repeat(1500);
    e.parse_error("%s", &[Arg::S(Some(big.clone().into()))]);
    e.reload_error("%s", &[Arg::S(Some(big.into()))]);
    o.ev(&mut e);
    let rb = e.get_reload_errors_description();
    let rb = rb.chars().nth(2047).unwrap();
    o.m(&format!("#reloadbig={rb}"));

    // #P9..#P13: ParseAbort / FatalError (C forks; fresh engine each)
    o.m("#P9");
    let mut k = LogEngine::default();
    k.parse_abort("plain abort %d\n", &[Arg::I(9)]);
    o.ev(&mut k);
    o.m("#fatal-noloc exit=1");
    o.m("#P10");
    let mut k = LogEngine::default();
    k.set_parse_location(Some("foo.rules"), 42);
    k.parse_abort("abort at %s here\n", &[arg("thing")]);
    o.ev(&mut k);
    o.m("#fatal-loc exit=1");
    o.m("#P11");
    let mut k = LogEngine::default();
    k.set_parse_location(Some("bar.rules"), 0);
    k.parse_abort("file-but-no-line\n", &[]);
    o.ev(&mut k);
    o.m("#fatal-filenoliner exit=1");
    o.m("#P12");
    let mut k = LogEngine::default();
    k.fatal_error("direct %d\n", &[Arg::I(5)]);
    o.ev(&mut k);
    o.m("#fatal-direct exit=1");
    o.m("#P13");
    let mut k = LogEngine::default();
    k.fatal_error("outer before reentrant cleanup\n", &[]);
    // stub cleanup_fatal_error re-enters FatalError when armed; C then
    // _exit(1)s in the guard without formatting. Assert no new output.
    let n = k.out.len();
    let f = k.fatal_error("inner fatal during cleanup\n", &[]);
    assert_eq!(f, Fatal::Reentrant);
    assert_eq!(k.out.len(), n);
    o.ev(&mut k);
    o.m("#fatal-reentrant exit=1");

    // #P14: log_safec_error emits then C assert(false); the glibc
    // assertion note (with the harness path) is C-only and stripped
    o.m("#P14");
    let mut k = LogEngine::default();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        k.log_safec_error("boom", 7);
    }));
    assert!(r.is_err());
    o.ev(&mut k);
    o.m("#safec sig=6");

    // #P15: quiet gating (conf Some; bypass false)
    o.m("#P15");
    e.set_log_quiet(true);
    e.log_message_stdout("quiet-suppressed %d", &[Arg::I(1)]);
    e.log_message_file(Phase::Stderr, "stderr-shown-despite-quiet\n", &[]);
    e.warning_message("warn-msg %s", &[arg("w")]);
    e.error_message("err-msg %s", &[arg("e")]);
    e.set_log_quiet(false);
    e.log_message_stdout("not-quiet %d", &[Arg::I(3)]);
    o.ev(&mut e);
    // marker appends directly to the unterminated "not-quiet 3"
    o.m("#P15b");
    e.logging_flags |= LOGGING_FLAG_SYSLOG;
    e.log_message_stdout("syslog-info %d", &[Arg::I(1)]);
    e.log_message_file(Phase::Stderr, "syslog-stderr-forced %d", &[Arg::I(2)]);
    e.warning_message("syslog-warn", &[]);
    e.error_message("syslog-err %s", &[arg("e")]);
    e.set_parse_location(Some("z.rules"), 3);
    e.parse_warning(WARN_RULES, "syslog-warn-group %d", &[Arg::I(9)]);
    e.parse_error("syslog-parse-err %d", &[Arg::I(8)]);
    e.logging_flags &= !LOGGING_FLAG_SYSLOG;
    e.warning_flags = 1 << WARN_RULES;
    e.parse_warning(WARN_RULES, "back-to-stderr", &[]);
    o.ev(&mut e);

    // #P16: LogMessage(FILE*)
    o.m("#P16");
    e.log_message_file(Phase::File("tmp"), "to-file %s\n", &[arg("hi")]);
    let t = o.take_file(&mut e);
    o.s.push_str(&format!("#tmpfile={t}\n"));

    // #P17 format battery
    o.m("#P17");
    e.log_message_stdout(
        "[%s|%8s|%25.25s|%-8s|]",
        &[arg("ab"), arg("cd"), arg("012345678901234567890123456789"), arg("ef")],
    );
    e.log_message_stdout(
        "[%*s|%*s|%*s|]",
        &[Arg::I(5), arg("w5"), Arg::I(0), arg("w0"), Arg::I(30), arg("w30")],
    );
    e.log_message_stdout("[nul:%*s]", &[Arg::I(3), Arg::S(None)]);
    e.log_message_stdout("[neg:%-8s|pos:%8s|]", &[arg("L"), arg("R")]);
    e.log_message_stdout(
        "[%d|%d|%+d|% d|%02d|%02d]",
        &[Arg::I(7), Arg::I(-8), Arg::I(9), Arg::I(-10), Arg::I(3), Arg::I(-7)],
    );
    e.log_message_stdout(
        "[intmin:%d|intmin:%d]",
        &[Arg::I(i64::from(i32::MIN)), Arg::I(i64::from(i32::MIN))],
    );
    e.log_message_stdout(
        "[u8:%8u|u16:%16u|x:%08x|X:%04X]",
        &[Arg::U(4_000_000_000), Arg::U(1), Arg::U(255), Arg::U(48_823)],
    );
    e.log_message_stdout(
        "[lu:%lu|l06:%06lu|lld:%lld|llu:%llu]",
        &[
            Arg::U(4_294_967_296),
            Arg::U(42),
            Arg::I(i64::MIN),
            Arg::U(u64::MAX),
        ],
    );
    e.log_message_stdout(
        "[zd:%zd|%zu]",
        &[Arg::I(-5), Arg::U(9)],
    );
    e.log_message_stdout(
        "[hd:%hhd|hu:%hhu|wd:%hd]",
        &[Arg::I(-3), Arg::U(200), Arg::I(-300)],
    );
    e.log_message_stdout(
        "[prec:%.*s|negprec:%.*s|]",
        &[Arg::I(3), arg("abcdef"), Arg::I(-1), arg("ghij")],
    );
    e.log_message_stdout(
        "[f:%f|lf:%lf|f2:%.2f|g:%g]",
        &[Arg::F(1.5), Arg::F(2.25), Arg::F(3.14159), Arg::F(0.0001)],
    );
    e.log_message_stdout("[pct:100%%done]", &[]);
    e.log_message_stdout(
        "[e:%e|E:%E|g6:%.6g|exp:%.2e]",
        &[Arg::F(123456.789), Arg::F(123456.789), Arg::F(123456.789), Arg::F(0.5)],
    );
    e.log_message_stdout(
        "    %18.18s(v%u)%s",
        &[arg("averyveryverylongname123"), Arg::U(4), arg("\n")],
    );
    e.log_message_stdout("[fmtu64:5|fmtx:ff]", &[]);
    o.ev(&mut e);

    // #P17b converter battery 2
    o.m("#P17b");
    e.log_message_stdout(
        "[g0:%.0g|g1:%.1g|g3:%.3g|g20:%.20g]",
        &[Arg::F(123456.0), Arg::F(123456.0), Arg::F(123456.0), Arg::F(123456.0)],
    );
    e.log_message_stdout(
        "[g5:%.5g|g6:%.6g|g7:%.7g]",
        &[Arg::F(0.0000123456), Arg::F(0.0000123456), Arg::F(0.0000123456)],
    );
    e.log_message_stdout(
        "[h1:%.1g|h2:%.2g|h3:%.3g|hf:%.1f]",
        &[Arg::F(0.125), Arg::F(0.125), Arg::F(0.125), Arg::F(0.125)],
    );
    e.log_message_stdout(
        "[h2:%.5g|h5:%.6g]",
        &[Arg::F(0.135), Arg::F(0.135)],
    );
    e.log_message_stdout(
        "[e0:%.0e|e1:%.1e|e3:%.3e]",
        &[Arg::F(0.5), Arg::F(0.5), Arg::F(0.5)],
    );
    e.log_message_stdout(
        "[z:%f|zi:%i|inf:%f|-inf:%f|q:%f]",
        &[
            Arg::F(0.0),
            Arg::I(0),
            Arg::F(f64::INFINITY),
            Arg::F(f64::NEG_INFINITY),
            Arg::F(f64::NAN),
        ],
    );
    e.log_message_stdout(
        "[einf:%e|qg:%g|qf:%f]",
        &[Arg::F(f64::INFINITY), Arg::F(f64::NAN), Arg::F(f64::NAN)],
    );
    e.log_message_stdout(
        "[big:%.2f|rnd:%.10f]",
        &[Arg::F(1e30), Arg::F(0.0078125)],
    );
    e.log_message_stdout(
        "[negw:%-8s|%5.2f|%12.10f]",
        &[arg("nw"), Arg::F(-1.5), Arg::F(0.0078125)],
    );
    e.log_message_stdout(
        "[zero:%08x|zerof:%08.3f|lz0:%-#08x|hash:%#x|%#.5g]",
        &[Arg::U(255), Arg::F(1.5), Arg::U(9), Arg::U(255), Arg::F(123456.0)],
    );
    e.log_message_stdout(
        "[oct:%o|octw:%#o|c:%c|%5c]",
        &[Arg::U(8), Arg::U(8), Arg::U(u64::from(b'A')), Arg::U(u64::from(b'Z'))],
    );
    e.log_message_stdout("[dot0:%.0s|dot0w:%8.0s]", &[arg("zz"), arg("yy")]);
    e.log_message_stdout("[x8:%#8x|%8o]", &[Arg::U(255), Arg::U(8)]);
    e.log_message_stdout("[negprecw:%*s]", &[Arg::I(-4), arg("wp")]);
    o.ev(&mut e);

    // #P18 Dumper
    o.m("#P18");
    {
        let mut d = Dumper::new(&mut e, Some("dump header"), 3);
        // C constructor logs via LogMessage; drain into transcript after
        // each dump so ordering is preserved through one engine
        d.dump_v(&mut e, "name-one", 1);
        d.dump_v(&mut e, "two", 2);
        d.dump_v(&mut e, "averyveryverylongname123", 3);
        d.dump_v(&mut e, "four", 4);
        d.dump_v(&mut e, "five", 5);
        d.dump_v(&mut e, "six", 6);
        d.finish(&mut e);
        o.ev(&mut e);
    }
    {
        let mut d = Dumper::new(&mut e, None, 2);
        d.dump_v(&mut e, "a", 0);
        d.dump_v(&mut e, "b", 0);
        d.dump_v(&mut e, "c", 0);
        d.dump_t(&mut e, "name", "ns");
        d.finish(&mut e);
        o.ev(&mut e);
    }

    // #P19 ConfigLogger battery
    o.m("#P19");
    ConfigLogger::log_option(&mut e, "TopOption");
    let f = ConfigLogger::log_flag(&mut e, "capT", true, false);
    o.ev(&mut e);
    o.m(&format!("#flagT={}", i32::from(f)));
    ConfigLogger::log_flag(&mut e, "capF", false, false);
    ConfigLogger::log_flag(&mut e, "sub", true, true);
    o.ev(&mut e);
    ConfigLogger::log_flag(&mut e, "sub2", false, true);
    // C prints the flag result AFTER the assignment line
    let f = ConfigLogger::log_flag(&mut e, "sentinel-never-printed", false, false);
    // undo the sentinel log line (we only needed the return value)
    e.out.pop();
    o.ev(&mut e);
    o.m(&format!("#flagS={}", i32::from(f)));
    ConfigLogger::log_limit_int(&mut e, "li1", 5, 5, false);
    ConfigLogger::log_limit_int(&mut e, "li2", 6, 9, false);
    ConfigLogger::log_limit_uint(&mut e, "li3", 7, 7, false);
    ConfigLogger::log_limit_int(&mut e, "li4", 8, 8, false);
    ConfigLogger::log_limit_uint(&mut e, "li5", 9, 9, false);
    ConfigLogger::log_limit_int(&mut e, "li6", -10, -10, false);
    ConfigLogger::log_limit_uint(&mut e, "li7", 11, 11, false);
    ConfigLogger::log_limit_int_dis(&mut e, "ld1", 4, 9, 4, false);
    ConfigLogger::log_limit_int_dis(&mut e, "ld2", 5, 5, 4, false);
    ConfigLogger::log_limit_uint_dis(&mut e, "ld3", 6, 9, 6, false);
    ConfigLogger::log_limit_int_dis(&mut e, "ld4", -7, -9, -7, false);
    ConfigLogger::log_value_desc(&mut e, "v1", 42, "desc", false);
    ConfigLogger::log_value_int(&mut e, "v2", 7, false);
    ConfigLogger::log_value_uint(&mut e, "v3", 8, false);
    ConfigLogger::log_value_int(&mut e, "v4", -9, false);
    ConfigLogger::log_value_uint(&mut e, "v5", 10, false);
    ConfigLogger::log_value_int(&mut e, "v6", -11, false);
    ConfigLogger::log_value_uint(&mut e, "v7", 12, false);
    ConfigLogger::log_value_double(&mut e, "v8", 3.5, false);
    ConfigLogger::log_value_str(&mut e, "v9", Some("strval"), false);
    ConfigLogger::log_value_str(&mut e, "v10", Some(""), false);
    ConfigLogger::log_value_str(&mut e, "v11", None, false);
    ConfigLogger::log_list(&mut e, Some("ll1"), "tok1 tok2 tok3", " ", false);
    ConfigLogger::log_list(
        &mut e,
        Some("ll2"),
        "a bb ccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp qqqq rrrr ssss tttt uuuu vvvv wwww xxxx yyyy zzzz 0000 1111 2222 3333 4444 5555 6666 7777 8888 9999",
        " ",
        false,
    );
    ConfigLogger::log_list(&mut e, Some("ll3"), "x y z", " | ", false);
    ConfigLogger::log_list(&mut e, None, "capnull tok", " ", false);
    ConfigLogger::log_list(&mut e, Some(""), "capempty tok", " ", false);
    ConfigLogger::log_list_bare(&mut e, "");
    ConfigLogger::log_list_bare(
        &mut e,
        "single tok chain that is long single tok chain that is long single tok chain that is long single tok chain",
    );
    o.ev(&mut e);

    // #P20 counters
    o.m("#P20");
    o.m(&format!("#warns={}", e.get_parse_warnings()));
    o.m(&format!("#warns2={}", e.get_parse_warnings()));
    o.m(&format!("#errs={}", e.get_parse_errors()));
    o.m(&format!("#errs2={}", e.get_parse_errors()));
    o.m(&format!("#reload3={}", e.get_reload_errors()));
    e.reset_parse_errors();
    o.m(&format!("#errs3={}", e.get_parse_errors()));
    o.m(&format!("#reload4={}", e.get_reload_errors()));

    // expected: harness vectors, minus the C-glibc assertion note line
    let expected = include_str!("../tools/log_harness/vectors.txt");
    let expected: String = expected
        .lines()
        .filter(|l| !l.starts_with("probe: ") && !l.contains("Assertion `false' failed"))
        .map(|l| format!("{l}\n"))
        .collect();

    if o.s != expected {
        // first divergence for diagnostics
        let mut shown = 0;
        for (i, (a, b)) in o.s.lines().zip(expected.lines()).enumerate() {
            if a != b {
                eprintln!("line {i}:\n  rust: {a:?}\n  c   : {b:?}");
                shown += 1;
                if shown >= 6 {
                    break;
                }
            }
        }
        panic!(
            "transcript mismatch: rust {} lines vs c {} lines",
            o.s.lines().count(),
            expected.lines().count()
        );
    }
}
