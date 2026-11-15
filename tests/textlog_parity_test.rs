#![allow(clippy::type_complexity, clippy::field_reassign_with_default)]
// Whole-transcript replay of tools/textlog_harness/vectors.txt: the C probe
// compiled ORIGINAL log/text_log.cc + main/thread.cc (+ real util.cc
// get_error and messages.cc) with a stubbed time(). This test drives
// text_log.rs + thread.rs against a fake clock and compares the merged
// stdout+stderr byte stream line for byte for line, including file
// contents dumped after each phase (the port's written bytes must match
// glibc snprintf/fwrite placement exactly).
use std::cell::RefCell;
use std::rc::Rc;

use snort3::log::messages::*;
use snort3::log::text_log::*;
use snort3::main::thread::*;
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
}

/// dump_file equivalent: stat + escaped content (printable ASCII kept,
/// everything else \xNN, exactly like the probe).
fn dump_file(o: &mut Out, p: &str) {
    match std::fs::metadata(p) {
        Err(_) => o.m(&format!("STAT fail {p}")),
        Ok(st) => {
            o.m(&format!("STAT ok {p} size={}", st.len()));
            match std::fs::read(p) {
                Err(_) => o.m(&format!("OPEN fail {p}")),
                Ok(bytes) => {
                    let mut esc = String::from("CONTENT [");
                    for b in bytes {
                        match b {
                            0x20..=0x7e => esc.push(b as char),
                            _ => esc.push_str(&format!("\\x{b:02x}")),
                        }
                    }
                    esc.push(']');
                    o.m(&esc);
                }
            }
        }
    }
}

/// dump_dir equivalent: sorted non-dot entries with stat sizes.
fn dump_dir(o: &mut Out) {
    let mut names: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(".") {
        for de in rd.flatten() {
            let n = de.file_name().to_string_lossy().into_owned();
            if !n.starts_with('.') {
                names.push(n);
            }
        }
    }
    names.sort();
    let mut line = String::from("DIR");
    for n in &names {
        let size = std::fs::metadata(n).map(|m| m.len()).unwrap_or(0);
        line.push_str(&format!(" {n}({size})"));
    }
    o.m(&line);
}

fn drain(sink: &StdoutSink, o: &mut Out) {
    let bytes = std::mem::take(&mut *sink.borrow_mut());
    let s = String::from_utf8_lossy(&bytes).into_owned();
    o.s.push_str(&s);
}

#[test]
fn text_log_transcript_parity() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/textlog_files");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::env::set_current_dir(&root).unwrap();

    let mut e = LogEngine::default();
    e.warning_flags = !0; // probe: messages default warning_flags ~0 for PERR
    let mut o = Out { s: String::new() };
    let mut ts = ThreadState::default();
    let mut conf = NamingConfig::default();
    let clock_cell: Rc<RefCell<u64>> = Rc::new(RefCell::new(1_000_000));
    let clock_cell2 = clock_cell.clone();
    let mut now: Clock = Box::new(move || *clock_cell2.borrow());
    let sink: StdoutSink = Rc::new(RefCell::new(Vec::new()));

    let reset = |ts: &mut ThreadState, conf: &mut NamingConfig| {
        *conf = NamingConfig::default();
        ts.instance_id = 0;
        ts.set_instance_max(1);
        ts.set_thread_type(SThreadType::Other);
    };

    o.m("=== A: naming (get_instance_file / get_main_file) ===");
    {
        o.m(&format!(
            "A1 {} / {}",
            get_instance_file(&conf, &ts, "a.log", &mut e),
            get_main_file(&conf, "a.log")
        ));
        e.out.clear();

        conf.log_dir = "L".into();
        o.m(&format!(
            "A2 {} / {}",
            get_instance_file(&conf, &ts, "a.log", &mut e),
            get_main_file(&conf, "a.log")
        ));
        e.out.clear();

        reset(&mut ts, &mut conf);
        conf.id_offset = 1;
        o.m(&format!(
            "A3 idoffset {}",
            get_instance_file(&conf, &ts, "a.log", &mut e)
        ));

        reset(&mut ts, &mut conf);
        conf.id_zero = true;
        o.m(&format!(
            "A4 idzero {}",
            get_instance_file(&conf, &ts, "a.log", &mut e)
        ));

        reset(&mut ts, &mut conf);
        ts.set_instance_max(3);
        ts.instance_id = 3;
        conf.id_offset = 1;
        o.m(&format!(
            "A5 max3 id3 off1 {}",
            get_instance_file(&conf, &ts, "a.log", &mut e)
        ));

        reset(&mut ts, &mut conf);
        conf.run_prefix = "pre".into();
        o.m(&format!(
            "A6 prefix {}",
            get_instance_file(&conf, &ts, "a.log", &mut e)
        ));

        reset(&mut ts, &mut conf);
        conf.run_prefix = "pre".into();
        ts.set_instance_max(2);
        o.m(&format!(
            "A7 prefix+max {}",
            get_instance_file(&conf, &ts, "a.log", &mut e)
        ));

        reset(&mut ts, &mut conf);
        conf.id_zero = true;
        ts.instance_id = 99_999_999;
        o.m(&format!(
            "A11 idtrunc {}",
            get_instance_file(&conf, &ts, "a.log", &mut e)
        ));

        reset(&mut ts, &mut conf);
        conf.run_prefix = "pre".into();
        conf.id_subdir = true;
        ts.set_instance_max(2);
        let n = get_instance_file(&conf, &ts, "a.log", &mut e);
        e.out.clear();
        o.m(&format!("A8 subdir ok {n}"));
        let n = get_instance_file(&conf, &ts, "a.log", &mut e);
        e.out.clear();
        o.m(&format!("A9 subdir again {n}"));

        reset(&mut ts, &mut conf);
        conf.run_prefix = "no/such".into();
        conf.id_subdir = true;
        ts.set_instance_max(2);
        o.m("A10 subdir deep (PERR follows)");
        let n = get_instance_file(&conf, &ts, "a.log", &mut e);
        o.ev(&mut e); // C: unbuffered stderr lands between the two printfs
        o.m(&format!("A10 name {n}"));
        reset(&mut ts, &mut conf); // probe: reset_conf() closes the A block
    }

    o.m("=== B: init buffer clamp + avail/reset ===");
    {
        let mut t =
            text_log_init("b1.log", 10, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        o.m(&format!("B1 init10_clamped avail={}", t.avail()));
        t.putc(b'q', &mut now, &mut e);
        o.m(&format!("B2 putc_then_reset avail={}", t.avail()));
        t.reset();
        o.m(&format!("B3 after_reset avail={}", t.avail()));
        let ok = t.putc(b'x', &mut now, &mut e);
        o.m(&format!("B4 putc ok={}", ok as i32));
        t.print("%s %d", &[Arg::S(Some("hello".into())), Arg::I(42)], &mut now, &mut e);
        text_log_term(Some(&mut t), &mut now, &mut e);
        dump_file(&mut o, "./b1.log");

        let mut t2 = text_log_init("b2.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        o.m(&format!("B5 init0 avail={}", t2.avail()));
        text_log_term(Some(&mut t2), &mut now, &mut e);
    }

    o.m("=== C: Write / Print / flush semantics ===");
    {
        let mut t =
            text_log_init("c1.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        for _ in 0..4096 {
            t.putc(b'a', &mut now, &mut e);
        }
        o.m(&format!("C1 after_fill pos_avail={}", t.avail()));
        let r = t.putc(b'!', &mut now, &mut e);
        o.m(&format!("C2 putc_at_full ok={} avail={}", r as i32, t.avail()));
        text_log_term(Some(&mut t), &mut now, &mut e);
        dump_file(&mut o, "./c1.log");

        let mut t2 =
            text_log_init("c2.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        let big = "B".repeat(5000);
        let r = t2.write(&big, 5000, &mut now, &mut e);
        o.m(&format!("C3 write5000 ok={} avail={}", r as i32, t2.avail()));
        text_log_term(Some(&mut t2), &mut now, &mut e);
        dump_file(&mut o, "./c2.log");

        let mut t3 =
            text_log_init("c3.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        let exact = "C".repeat(4095);
        let r = t3.print("%s", &[Arg::S(Some(exact.into()))], &mut now, &mut e);
        o.m(&format!("C4 exact_fill ok={} avail={}", r as i32, t3.avail()));
        let r = t3.print("tail", &[], &mut now, &mut e);
        o.m(&format!("C5 overflow_at_full ok={} avail={}", r as i32, t3.avail()));
        text_log_term(Some(&mut t3), &mut now, &mut e);
        dump_file(&mut o, "./c3.log");

        let mut t4 =
            text_log_init("c4.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        let huge = "D".repeat(8999);
        let r = t4.print("%s", &[Arg::S(Some(huge.into()))], &mut now, &mut e);
        o.m(&format!("C6 huge_print ok={} avail={}", r as i32, t4.avail()));
        let r = t4.print("T", &[], &mut now, &mut e);
        o.m(&format!("C7 after_huge_print_T avail={}", t4.avail()));
        let _ = r;
        t4.putc(b'Z', &mut now, &mut e);
        text_log_term(Some(&mut t4), &mut now, &mut e);
        dump_file(&mut o, "./c4.log");

        let mut t5 =
            text_log_init("c5.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t5.write("abcdef", -3, &mut now, &mut e);
        o.m(&format!("C8 neg_write avail={}", t5.avail()));
        let rb1 = t5.write("ab", 5, &mut now, &mut e);
        o.m(&format!(
            "C8b padded_ret ok={} avail={}",
            rb1 as i32,
            t5.avail()
        ));
        let rb2 = t5.write("ab", -3, &mut now, &mut e);
        o.m(&format!(
            "C8c pad_neg ok={} avail={}",
            rb2 as i32,
            t5.avail()
        ));
        t5.flush(&mut now, &mut e);
        text_log_term(Some(&mut t5), &mut now, &mut e);
        dump_file(&mut o, "./c5.log");

        let mut t6 =
            text_log_init("c6.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        let fl = t6.flush(&mut now, &mut e);
        o.m(&format!("C9 flush_empty ok={}", fl as i32));
        text_log_term(Some(&mut t6), &mut now, &mut e);
        text_log_term(None, &mut now, &mut e);
        o.m("C10 term_null_survived");
    }

    o.m("=== D: Quote ===");
    {
        let mut t =
            text_log_init("d1.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t.quote("plain", &mut now, &mut e);
        t.putc(b'\n', &mut now, &mut e);
        t.quote("has\"quote and \\back\\", &mut now, &mut e);
        t.putc(b'\n', &mut now, &mut e);
        t.quote("", &mut now, &mut e);
        t.quote(&"\"".repeat(7000), &mut now, &mut e);
        text_log_term(Some(&mut t), &mut now, &mut e);
        dump_file(&mut o, "./d1.log");
    }

    o.m("=== E: append size + roll ===");
    {
        let mut t =
            text_log_init("e1.log", 0, 100, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t.print("0123456789", &[], &mut now, &mut e);
        t.flush(&mut now, &mut e);
        o.m(&format!("E1 avail={}", t.avail()));
        t.print(&"ABCDEFGHIJ".repeat(5), &[], &mut now, &mut e);
        t.print(&"ABCDEFGHIJ".repeat(5), &[], &mut now, &mut e);
        o.m(&format!("E2 before_flush avail={}", t.avail()));
        t.flush(&mut now, &mut e);
        t.print("tail\n", &[], &mut now, &mut e);
        text_log_term(Some(&mut t), &mut now, &mut e);
        dump_file(&mut o, "./e1.log");
        dump_dir(&mut o);

        reset(&mut ts, &mut conf);
        let mut t2 =
            text_log_init("e2.log", 0, 10, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t2.print("0123456789", &[], &mut now, &mut e);
        t2.flush(&mut now, &mut e);
        *clock_cell.borrow_mut() += 1;
        t2.print("x", &[], &mut now, &mut e);
        t2.flush(&mut now, &mut e);
        t2.print("y", &[], &mut now, &mut e);
        t2.flush(&mut now, &mut e);
        *clock_cell.borrow_mut() += 1;
        t2.print("zz", &[], &mut now, &mut e);
        t2.flush(&mut now, &mut e);
        text_log_term(Some(&mut t2), &mut now, &mut e);
        dump_dir(&mut o);

        let mut t3 =
            text_log_init("e1.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t3.print("appended\n", &[], &mut now, &mut e);
        text_log_term(Some(&mut t3), &mut now, &mut e);
        dump_file(&mut o, "./e1.log");
    }

    o.m("=== F: stdout special ===");
    {
        let mut t =
            text_log_init("stdout", 0, 10, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t.print("OUT1\n", &[], &mut now, &mut e);
        let f = t.flush(&mut now, &mut e);
        drain(&sink, &mut o);
        o.m(&format!("F1 flushed={}", f as i32));
        t.print("OUT2\n", &[], &mut now, &mut e);
        text_log_term(Some(&mut t), &mut now, &mut e);
        drain(&sink, &mut o);
        dump_dir(&mut o);
    }

    o.m("=== G: naming in TextLog_Init by thread type ===");
    {
        reset(&mut ts, &mut conf);
        conf.run_prefix = "pp".into();
        ts.set_thread_type(SThreadType::Main);
        let mut t =
            text_log_init("g1.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        o.m("G1 main_thread init");
        t.print("main\n", &[], &mut now, &mut e);
        text_log_term(Some(&mut t), &mut now, &mut e);
        ts.set_thread_type(SThreadType::Packet);
        let mut t2 =
            text_log_init("g1.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        o.m("G2 pkt_thread init max1 no id");
        t2.print("pkt\n", &[], &mut now, &mut e);
        text_log_term(Some(&mut t2), &mut now, &mut e);
        ts.set_thread_type(SThreadType::Other);
        dump_dir(&mut o);
        ts.set_thread_type(SThreadType::Main);
    }

    o.m("=== G2: syslog routing of open errors + roll rename fail ===");
    {
        e.logging_flags |= LOGGING_FLAG_SYSLOG;
        let t = text_log_init(
            "/probesurelynotthere/y.log",
            0,
            0,
            false,
            &ts,
            &conf,
            &mut e,
            &mut now,
            &sink,
        );
        o.ev(&mut e);
        o.m(&format!(
            "G2a syslog_noncrit init={}",
            if t.is_some() { "nonnull" } else { "null" }
        ));
        e.logging_flags &= !LOGGING_FLAG_SYSLOG;
    }

    o.m("=== H: fatal / error open paths ===");
    {
        reset(&mut ts, &mut conf);
        ts.set_thread_type(SThreadType::Main);

        // H4 (C ran the roll-reopen-fatal path in a forked child)
        o.m("FORK H4");
        e.already_fatal = false; // new process
        std::fs::create_dir("gone").unwrap();
        conf.log_dir = "gone".into();
        let mut t4 =
            text_log_init("h4.log", 0, 10, true, &ts, &conf, &mut e, &mut now, &sink).unwrap();
        t4.print("0123456789", &[], &mut now, &mut e);
        t4.flush(&mut now, &mut e);
        std::fs::remove_file("gone/main_h4.log").unwrap();
        std::fs::remove_dir("gone").unwrap();
        *clock_cell.borrow_mut() += 10;
        t4.print("x", &[], &mut now, &mut e);
        let _ = t4.flush(&mut now, &mut e);
        o.ev(&mut e);
        o.m("EXIT H4 code=1");
        // the C child's log_dir edit died with the child; parent conf clean
        conf.log_dir.clear();

        o.m("FORK H1");
        e.already_fatal = false;
        let t = text_log_init(
            "no/such/dir/x.log",
            0,
            0,
            true,
            &ts,
            &conf,
            &mut e,
            &mut now,
            &sink,
        );
        let _ = t;
        o.ev(&mut e);
        o.m("EXIT H1 code=1");

        o.m("FORK H2");
        e.already_fatal = false;
        let t =
            text_log_init("/probesurelynotthere/x.log", 0, 0, true, &ts, &conf, &mut e, &mut now, &sink);
        let _ = t;
        o.ev(&mut e);
        o.m("EXIT H2 code=1");

        let t = text_log_init(
            "/probesurelynotthere/x.log",
            0,
            0,
            false,
            &ts,
            &conf,
            &mut e,
            &mut now,
            &sink,
        );
        o.ev(&mut e);
        o.m(&format!(
            "H3 noncritical init={}",
            if t.is_some() { "nonnull" } else { "null" }
        ));
        dump_dir(&mut o);
    }

    let got = o.s.clone();
    let want = include_str!("../tools/textlog_harness/vectors.txt");
    if got != want {
        let g: Vec<&str> = got.lines().collect();
        let w: Vec<&str> = want.lines().collect();
        let mut shown = 0;
        for i in 0..g.len().max(w.len()) {
            let a = g.get(i).copied().unwrap_or("<eof>");
            let b = w.get(i).copied().unwrap_or("<eof>");
            if a != b {
                let ta: String = a.chars().take(70).collect();
                let tb: String = b.chars().take(70).collect();
                eprintln!("line {}: rust={ta:?}\n      c   ={tb:?}", i + 1);
                shown += 1;
                if shown >= 8 {
                    break;
                }
            }
        }
        panic!("textlog transcript mismatch (rust {} lines, c {} lines)", g.len(), w.len());
    }
    assert_eq!(want.lines().count(), 87);
}
