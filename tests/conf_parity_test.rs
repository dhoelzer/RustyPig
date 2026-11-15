#![allow(clippy::type_complexity, clippy::field_reassign_with_default, clippy::useless_format)]
// Whole-transcript replay of tools/conf_harness/vectors.txt: the C probe
// compiled ORIGINAL parser/parse_conf.cc + parser/config_file.cc against
// the original log/messages.cc engine. This test drives ParseConf +
// ConfFiles + checksum parsing + the LogEngine through the identical call
// sequence and compares the merged stdout+stderr byte stream line for
// line. The filesystem is laid out identically under target/conf_files
// (relative paths only, so Loading/Finished lines replay exactly).
use std::cell::RefCell;
use std::rc::Rc;
use snort3::log::messages::*;
use snort3::parser::config_file::*;
use snort3::parser::messages::ParseMsg;
use snort3::parser::parse_conf::*;
use snort3::main::policy::{IpsPolicy, NetworkPolicy};
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

fn a(s: &str) -> Arg<'_> {
    Arg::S(Some(s.to_string().into()))
}

/// drain the VarContext diag sink into LogEngine with messages.cc framing
/// (ERROR/WARNING/FATAL types + the location prefix handled there).
fn relay(ctx: &mut snort3::parser::vars::VarContext, e: &mut LogEngine) {
    for m in ctx.diag.drain(..) {
        match m {
            ParseMsg::Error(s) => e.parse_error("%s", &[a(&s)]),
            ParseMsg::Warning(g, s) => e.parse_warning(g, "%s", &[a(&s)]),
            ParseMsg::Abort(s) => {
                e.parse_abort("%s", &[a(&s)]);
            }
        }
    }
}

/// The probe's stub parse_stream: each reaching re-enters parse_include
/// while a budget lasts (recursive closure factory mirrors g_nested_count).
fn make_seam(
    na: Rc<RefCell<Option<String>>>,
    nc: Rc<RefCell<i32>>,
) -> Box<
    dyn FnMut(
        &mut ParseConf,
        &mut snort3::parser::vars::VarContext,
        &mut SnortConfig,
        &ConfFiles,
        &IpsPolicy,
        &mut LogEngine,
    ),
> {
    Box::new(move |pc, ctx, conf, cf, ip, e| {
        if *nc.borrow() > 0 {
            *nc.borrow_mut() -= 1;
            let arg = na.borrow().clone().unwrap();
            pc.parse_include(
                &arg,
                ctx,
                conf,
                cf,
                ip,
                e,
                Some(&mut make_seam(Rc::clone(&na), Rc::clone(&nc))),
            );
        }
    })
}

#[test]
fn conf_transcript_parity() {
    // ---- filesystem layout (mirror of the harness) --------------------
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("conf_files");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for d in ["sub", "incdir", "adir"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::env::set_current_dir(&root).unwrap();
    std::fs::write("/tmp/confprobe_outside.rules", "x\n").unwrap();

    let mut e = LogEngine::default();
    e.warning_flags = !0; // probe: SnortConfig::warning_flags = ~0u
    let mut o = Out { s: String::new() };

    let mut conf_files = ConfFiles::default();
    let mut pc = ParseConf::new();
    let mut conf = SnortConfig::default();
    let mut ip = IpsPolicy::new(0);
    let mut netpol = NetworkPolicy::default();
    let mut vartab = snort3::sfip::sf_vartable::Vartable::new();
    let mut pvt = snort3::ports::port_var_table::PortVarTable::create();
    let mut ctx = snort3::parser::vars::VarContext::new(&mut vartab, &mut pvt);

    // The parse_stream seam: witness counter lives in ParseConf; nested
    // re-entry is driven by the g_nested_count analog below.
    let nested_arg: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let nested_count: Rc<RefCell<i32>> = Rc::new(RefCell::new(0));

    // ===================================================================
    o.m("#A1");
    let cases: [Option<&str>; 25] = [
        None, Some(""), Some("all"), Some("none"), Some("ip"), Some("tcp"), Some("udp"),
        Some("icmp"), Some("noip"), Some("notcp"), Some("noudp"), Some("noicmp"),
        Some("ip tcp"), Some("ip noip"), Some("noip notcp"), Some("all none"),
        Some("none all"), Some("ip ip"), Some("ip all notcp"), Some("bogus"),
        Some("ip bogus"), Some("bogus ip"), Some("ip  tcp"), Some("ip\tudp"), Some("  "),
    ];
    for ca in cases {
        config_checksum_drop(ca, &mut netpol, &mut e);
        config_checksum_mode(ca, &mut netpol, &mut e);
        relay(&mut ctx, &mut e);
        o.ev(&mut e);
        let arglabel = ca.unwrap_or("(null)");
        o.m(&format!(
            "CK args={arglabel} drop={:x} eval={:x} reads={}",
            netpol.checksum_drop, netpol.checksum_eval, pc.stream_reads
        ));
    }

    // ===================================================================
    o.m("#B1");
    for f in [
        "/etc/snort/snort.lua", "snort.lua", "./x.lua", "a/b", "a/", "/x",
        "dir with space/f.lua",
    ] {
        conf_files.config_conf(f);
        o.m(&format!("CONF conf {}", conf_files.get_snort_conf()));
        o.m(&format!("CONF dir {}", conf_files.get_snort_conf_dir()));
    }

    // ===================================================================
    o.m("#C1");
    {
        let (f, l) = pc.get_parse_location();
        o.m(&format!("LOC empty file {}", f.unwrap_or("(null)")));
        o.m(&format!("LOC line={}", l));
        o.m(&format!("LOC file_get {}", pc.get_parse_file(&conf_files)));

        pc.push_parse_location(Some("A"), Some("/abs/main.rules"), Some("/abs/main.rules"), 0, &conf, &mut e);
        o.ev(&mut e);
        let (f, l) = pc.get_parse_location();
        let path = pc.get_parse_file(&conf_files).to_string();
        o.m(&format!(
            "LOC1 file={} path={} line={}",
            f.unwrap_or("(null)"),
            path,
            l
        ));
        pc.inc_parse_position(&mut e);
        pc.inc_parse_position(&mut e);
        let (f, l) = pc.get_parse_location();
        let _ = f;
        o.m(&format!("LOC1b line={}", l));
        pc.push_parse_location(Some("I"), Some("inc.rules"), None, 0, &conf, &mut e);
        o.ev(&mut e);
        let (f, _) = pc.get_parse_location();
        let path = pc.get_parse_file(&conf_files).to_string();
        o.m(&format!("LOC2 file={} path={}", f.unwrap_or("(null)"), path));
        pc.pop_parse_location(&conf, &mut e);
        o.ev(&mut e);
        let (f, l) = pc.get_parse_location();
        o.m(&format!("LOCback file={} line={}", f.unwrap_or("(null)"), l));
        pc.push_parse_location(Some("C"), Some("code1p.rules"), Some("x.rules"), 7, &conf, &mut e);
        pc.pop_parse_location(&conf, &mut e);
        pc.pop_parse_location(&conf, &mut e);
        o.ev(&mut e);
        let (f, _) = pc.get_parse_location();
        o.m(&format!("LOCempty file={}", f.unwrap_or("(null)")));
        o.m(&format!("LOC file_get2 {}", pc.get_parse_file(&conf_files)));
        pc.pop_parse_location(&conf, &mut e); // empty stack: no-op
        o.ev(&mut e);
    }
    o.m("#C2");
    pc.push_parse_location(Some("A"), None, Some("x"), 0, &conf, &mut e);
    {
        let (f, _) = pc.get_parse_location();
        o.m(&format!("LOCnullpush file={}", f.unwrap_or("(null)")));
    }
    o.m("#C3: show_file_codes on");
    conf.set_show_file_codes(true);
    pc.push_parse_location(Some("I"), Some("p1.rules"), Some("p1.rules"), 0, &conf, &mut e);
    pc.pop_parse_location(&conf, &mut e);
    conf.set_show_file_codes(false);
    o.ev(&mut e);
    o.m("#C4: empty code -> ?");
    pc.push_parse_location(Some(""), Some("p2.rules"), Some("p2.rules"), 0, &conf, &mut e);
    pc.pop_parse_location(&conf, &mut e);
    o.ev(&mut e);
    o.m("#C6: empty code, show_file_codes on (distinct from null '?')");
    conf.set_show_file_codes(true);
    pc.push_parse_location(Some(""), Some("e.rules"), Some("e.rules"), 0, &conf, &mut e);
    pc.pop_parse_location(&conf, &mut e);
    conf.set_show_file_codes(false);
    o.ev(&mut e);
    o.m("#C5: null code -> ? with show_file_codes on");
    conf.set_show_file_codes(true);
    pc.push_parse_location(None, Some("q.rules"), Some("q.rules"), 7, &conf, &mut e);
    o.ev(&mut e);
    {
        let (f, l) = pc.get_parse_location();
        o.m(&format!("C5 file={} line={}", f.unwrap_or("(null)"), l));
    }
    pc.pop_parse_location(&conf, &mut e);
    conf.set_show_file_codes(false);
    o.ev(&mut e);

    // ===================================================================
    conf_files.config_conf("snort.conf");
    std::fs::create_dir_all("sub").unwrap();
    std::fs::create_dir_all("incdir").unwrap();
    std::fs::create_dir_all("adir").unwrap();
    o.m("#D1");
    pc.push_parse_location(Some("F"), Some("sub/main.rules"), Some("sub/main.rules"), 1, &conf, &mut e);
    o.ev(&mut e);
    for p in ["sub/target.rules", "incdir/target.rules", "target.rules"] {
        std::fs::write(p, "x\n").unwrap();
    }
    {
        let mut f: Vec<u8> = Vec::new();
        let code = pc.get_config_file("target.rules", &mut f, &conf, &conf_files);
        o.m(&format!(
            "GC1 code-none file {}",
            String::from_utf8_lossy(&f)
        ));
        o.m(&format!("GC1 code={}", code.unwrap_or("(null)")));

        conf.include_path = "incdir".into();
        let mut f2: Vec<u8> = b"sub/main.rules".to_vec();
        let code = pc.get_config_file("target.rules", &mut f2, &conf, &conf_files);
        o.m(&format!("GC3 file {}", String::from_utf8_lossy(&f2)));
        o.m(&format!("GC3 code={}", code.unwrap_or("(null)")));
        conf.include_path = "".into();
    }
    pc.pop_parse_location(&conf, &mut e);
    o.ev(&mut e);
    {
        let mut f: Vec<u8> = Vec::new();
        let code = pc.get_config_file("target.rules", &mut f, &conf, &conf_files);
        o.m(&format!("GC4 file {}", String::from_utf8_lossy(&f)));
        o.m(&format!("GC4 code={}", code.unwrap_or("(null)")));

        let mut f = Vec::new();
        let code = pc.get_config_file("./target.rules", &mut f, &conf, &conf_files);
        o.m(&format!("GC5 file {}", String::from_utf8_lossy(&f)));
        o.m(&format!("GC5 code={}", code.unwrap_or("(null)")));

        let mut f = Vec::new();
        let code = pc.get_config_file("/tmp/confprobe_outside.rules", &mut f, &conf, &conf_files);
        o.m(&format!(
            "GC6 code={} file={}",
            code.unwrap_or("(null)"),
            String::from_utf8_lossy(&f)
        ));

        let mut f = Vec::new();
        let code = pc.get_config_file("nope.rules", &mut f, &conf, &conf_files);
        o.m(&format!(
            "GC7 code={} file-after={}",
            code.unwrap_or("(null)"),
            String::from_utf8_lossy(&f)
        ));

        conf.include_path = "/nonexistent".into();
        let mut f = Vec::new();
        let code = pc.get_config_file("nope.rules", &mut f, &conf, &conf_files);
        o.m(&format!("GC8 code={}", code.unwrap_or("(null)")));
        conf.include_path = "".into();
    }
    o.m("#D1b: absolute arg is returned without any existence check");
    {
        let mut f = Vec::new();
        let code = pc.get_config_file("/absent/deep/rules.rules", &mut f, &conf, &conf_files);
        o.m(&format!(
            "GC10 code={} file={}",
            code.unwrap_or("(null)"),
            String::from_utf8_lossy(&f)
        ));
    }
    o.m("#D2: empty-string arg via relative walk");
    {
        let mut f = Vec::new();
        let code = pc.get_config_file("", &mut f, &conf, &conf_files);
        o.m(&format!("GC9 code={}", code.unwrap_or("(null)")));
    }

    // ===================================================================
    o.m("#E1");
    conf_files.config_conf("snort.conf");
    std::fs::write("b.rules", "x\n").unwrap();
    ip.includer = "a.rules".into();
    pc.parse_include("b.rules", &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    relay(&mut ctx, &mut e);
    o.ev(&mut e);
    o.m(&format!("E1 reads={}", pc.stream_reads));
    let (f, _) = pc.get_parse_location();
    o.m(&format!("E1 top file={}", f.unwrap_or("(null)")));

    o.m("#E2");
    pc.parse_include("missing.rules", &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    relay(&mut ctx, &mut e);
    o.ev(&mut e);

    o.m("#E3: $VAR expansion (ExpandVars is the var-layer glue under test)");
    snort3::parser::vars::parse_path_var(&mut ctx, "PNAME", Some("b.rules")).ok();
    relay(&mut ctx, &mut e);
    pc.parse_include("$PNAME", &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    relay(&mut ctx, &mut e);
    o.ev(&mut e);

    o.m("#E4: ParseIpVar outcomes through the REAL callback");
    for (n, v) in [
        ("$NETX", "[2.2.2.2]"), ("$NETX", "[3.3.3.3]"), ("$NETBAD", "[x]"),
        ("$NETANY", "!any"), ("$NETARG", ""), ("$NETW", "$UNDEF"),
        ("$NETW2", "1.2.3.4/33"),
    ] {
        let r = snort3::parser::vars::parse_ip_var(&mut ctx, n, v);
        relay(&mut ctx, &mut e);
        o.ev(&mut e);
        let idx = match &*format!("{}", n) {
            "$NETX" if v == "[2.2.2.2]" => 1,
            "$NETX" => 2,
            "$NETBAD" => 3,
            "$NETANY" => 4,
            "$NETARG" => 5,
            "$NETW" => 6,
            _ => 7,
        };
        o.m(&format!("R{}={}", idx, if r.unwrap_or(false) { 1 } else { 0 }));
    }
    // resolve_nets(): reruns the callback under the resolving flag
    let rr = snort3::parser::vars::resolve_nets(&mut ctx);
    relay(&mut ctx, &mut e);
    o.ev(&mut e);
    o.m(&format!("R8={}", if ctx.is_resolving_nets() { 1 } else { 0 }));
    let _ = rr;
    let r9 = snort3::parser::vars::parse_ip_var(&mut ctx, "$NETW", "[5.5.5.5]");
    relay(&mut ctx, &mut e);
    o.ev(&mut e);
    o.m(&format!("R9={}", if r9.unwrap_or(false) { 1 } else { 0 }));

    o.m("#E5: parse_rules_string depth witness");
    pc.parse_rules_string(
        "alert ip any any -> any any (sid:1;)\n", true,
        &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    relay(&mut ctx, &mut e);
    o.ev(&mut e);
    o.m(&format!("E5 reads={}", pc.stream_reads));

    o.m("#E6: rules-file open fail");
    pc.parse_rules_file(None, &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    pc.parse_rules_file(Some("adir"), &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    pc.parse_rules_file(Some("nope.rules"), &mut ctx, &mut conf, &conf_files, &ip, &mut e, None);
    relay(&mut ctx, &mut e);
    o.ev(&mut e);
    o.m(&format!("E6 reads={}", pc.stream_reads));

    o.m("#E7: get_rule_list walks sc->rule_lists");
    {
        let dl = Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let dl2 = Rc::clone(&dl);
        let n3 = Rc::new(RuleListNode { name: "third".into(), rule_list: None, next: None });
        let n2 = Rc::new(RuleListNode { name: "second".into(), rule_list: Some(dl2), next: Some(Rc::clone(&n3)) });
        let n1 = Rc::new(RuleListNode { name: "first".into(), rule_list: Some(Rc::clone(&dl)), next: Some(Rc::clone(&n2)) });
        conf.rule_lists = Some(n1);
        let r = ParseConf::get_rule_list(&conf, "second");
        let hit = r.map(|rr| Rc::ptr_eq(&rr, &dl)).unwrap_or(false);
        o.m(&format!("RL second={}", if hit { 1 } else { 0 }));
        let r = ParseConf::get_rule_list(&conf, "nope");
        o.m(&format!("RL nope={}", if r.is_some() { 1 } else { 0 }));
    }

    for p in ["outer.rules", "sub/b.rules", "sub/holder2.rules", "sub/holder.rules", "SPECIAL_INCLUDER"] {
        std::fs::write(p, "x\n").unwrap();
    }
    conf.include_path = "".into();

    o.m("#E8: nested include via rules_file (depth != 0)");
    ip.includer = "nonexistent-seed.rules".into();
    nested_arg.replace(Some("b.rules".into()));
    nested_count.replace(2);
    pc.parse_rules_file(Some("outer.rules"), &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    nested_arg.replace(None);
    o.ev(&mut e);

    o.m("#E9: parse_rules_string(ips_policy=false) -> special includer");
    conf.set_special_includer("SPECIAL_INCLUDER");
    nested_arg.replace(Some("b.rules".into()));
    nested_count.replace(1);
    pc.parse_rules_string("x", false, &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    o.ev(&mut e);

    o.m("#E10: nested include at depth != 0 (seed = get_parse_file)");
    nested_arg.replace(Some("b.rules".into()));
    nested_count.replace(2);
    pc.parse_rules_file(Some("outer.rules"), &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    nested_arg.replace(None);
    o.ev(&mut e);

    o.m("#E11: parse_rules_string(ips_policy=false) -> special includer seed");
    nested_arg.replace(Some("b.rules".into()));
    nested_count.replace(1);
    pc.parse_rules_string("x2", false, &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    o.ev(&mut e);

    o.m("#E12: parse_rules_string(ips_policy=true) -> policy includer seed");
    ip.includer = "sub/holder.rules".into();
    nested_arg.replace(Some("holder2.rules".into()));
    nested_count.replace(1);
    pc.parse_rules_string("x", true, &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    nested_arg.replace(None);
    o.ev(&mut e);
    o.m(&format!("E10 includer-unchanged={}", ip.includer));

    o.m("#E13: include_path wins over the depth seed");
    nested_arg.replace(Some("x/none-here.rules".into()));
    nested_count.replace(1);
    conf.include_path = "incdir".into();
    pc.parse_rules_file(Some("outer.rules"), &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    nested_arg.replace(Some("target.rules".into()));
    nested_count.replace(1);
    pc.parse_rules_file(Some("outer.rules"), &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    nested_arg.replace(None);
    conf.include_path = "".into();
    o.ev(&mut e);

    o.m("#E14: special seed at depth 0, full miss");
    nested_arg.replace(Some("holder2.rules".into()));
    nested_count.replace(1);
    pc.parse_rules_string("x", false, &mut ctx, &mut conf, &conf_files, &ip, &mut e,
        Some(&mut make_seam(Rc::clone(&nested_arg), Rc::clone(&nested_count))));
    relay(&mut ctx, &mut e);
    nested_arg.replace(None);
    o.ev(&mut e);

    o.m(&format!("#F1 counters err={} warn={}", e.get_parse_errors(), e.get_parse_warnings()));
    o.m(&format!("#F2 counters2 err={} warn={}", e.get_parse_errors(), e.get_parse_warnings()));

    let expected = include_str!("../tools/conf_harness/vectors.txt");
    let got = o.s;
    if got != expected {
        let mut shown = 0;
        for (i, (g, x)) in got.lines().zip(expected.lines()).enumerate() {
            if g != x {
                eprintln!("line {}: got  {:?}\n       want {:?}", i + 1, g, x);
                shown += 1;
                if shown >= 6 {
                    break;
                }
            }
        }
        if got.lines().count() != expected.lines().count() {
            eprintln!(
                "line count: got {}, want {}",
                got.lines().count(),
                expected.lines().count()
            );
        }
        panic!("conf transcript mismatch");
    }
    assert_eq!(expected.lines().count(), 161);
}
