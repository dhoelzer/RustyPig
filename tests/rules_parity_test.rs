// Whole-transcript replay of tools/rules_harness/vectors.txt. The C probe
// compiled ORIGINAL parse_rule.cc + parser.cc (RTN lifecycle) + rules.cc
// (RuleStateMap) + signature.cc (OtnLookup) + sfrim.cc (RuleIndexMap) +
// log_stats.cc (LogLabel/LogCount), with the ips_options meta layer
// test-doubled at the IpsManager::option_* seam. This test drives the Rust
// port through the identical call sequence (probe.cc mirrored 1:1) and
// compares the merged stdout+stderr line stream against the locked
// transcript: the in-process body plus both FATAL_DEMO subprocess blocks.
//
// C printf argument quirks that surface in the transcript are reproduced
// with comments at each call site.
#![allow(clippy::type_complexity, dead_code, unused_variables)]

use snort3::detection::parse_rule::*;
use snort3::detection::rules::{new_rule_state, rule_state_apply, RuleKey};
use snort3::detection::signature::{otn_lookup, OtnMap};
use snort3::detection::treenodes::RuleListNode;
use snort3::detection::sfrim::{
    rule_index_map_add, rule_index_map_create, rule_index_map_free, rule_index_map_get,
};
use snort3::detection::treenodes::{OtnHandle, RuleTreeNode, RtnHandle};
use snort3::framework::ips_action::IpsActionPriority;
use snort3::log::messages::Fatal;
use snort3::main::policy::{Enable, IpsPolicy};
use snort3::parser::config_file::ConfFiles;
use snort3::parser::parse_conf::{ParseConf, SnortConfig};

// ----------------------------------------------------------------------
// Rep: probe mirror. `out` is the merged stdout+stderr stream; the Rust
// LogEngine buffers ERROR/FATAL emitted by ported code, and every raw
// print drains it first so lines interleave in true call order (C probe
// pinned stdout unbuffered).
// ----------------------------------------------------------------------
struct Rep {
    sc: RuleCoreState,
    // parse_conf.cc file-statics the REAL parse_stream threads (the probe
    // drives the real parse_rules_string on these).
    pc: ParseConf,
    conf: SnortConfig,
    conf_files: ConfFiles,
    // get_token statics (prev/pos) + counters: C keeps them process-wide;
    // one StreamCtx spans every parse_rules_string call.
    sctx: snort3::parser::parse_stream::StreamCtx,
    out: Vec<String>,
}

impl Rep {
    fn new() -> Rep {
        Rep {
            sc: RuleCoreState::new(),
            pc: ParseConf::new(),
            conf: SnortConfig::default(),
            conf_files: ConfFiles::default(),
            sctx: snort3::parser::parse_stream::StreamCtx::default(),
            out: Vec::new(),
        }
    }
}

fn vname(v: &Option<snort3::sfip::sf_ipvar::SfIpVar>) -> String {
    match v {
        None => "NIL".to_string(),
        Some(v) => match &v.name {
            Some(n) => n.clone(),
            None => "~".to_string(),
        },
    }
}

fn po_name(po: &Option<snort3::ports::port_var_table::PoHandle>, fallback: &str) -> String {
    match po {
        None => "NIL".to_string(),
        Some(h) => match &h.borrow().name {
            Some(n) => n.clone(),
            None => fallback.to_string(),
        },
    }
}

impl Rep {
    fn p(&mut self, s: &str) {
        self.drain();
        self.out.push(s.to_string());
    }

    fn drain(&mut self) {
        for ev in self.sc.log.out.drain(..) {
            // One LogEvent may carry embedded newlines and even its own
            // trailing blank line (ParseError("can't open %s\n") keeps the
            // format's \n AND log_message appends one -> a real blank
            // transcript line, pinned after S3). Byte-faithful split: pop
            // ONE trailing empty piece (the terminator); keep interior
            // blanks. Then apply the build.sh line filter (grep split).
            let mut pieces: Vec<&str> = ev.text.split('\n').collect();
            if pieces.last().copied() == Some("") {
                pieces.pop();
            }
            for line in pieces {
                self.out.push(line.trim_end().to_string());
            }
        }
    }

    // dump_rtn (probe.cc:45): C printf feeds probe_action_name(rtn->action)
    // (static-snapshot aliasing is irrelevant single-call here).
    /// The probe's real parse_rules_string over the REAL ported stream:
    /// set s_ips_policy, then parse_stream (C stringstream path). Fatal
    /// port aborts flow out as Err(Fatal) exactly where C's FatalError
    /// terminated the process.
    fn stream_rules(&mut self, s: &str) -> Result<(), Fatal> {
        self.stream_rules_owned(s)
    }
    fn stream_rules_owned(&mut self, s: &str) -> Result<(), Fatal> {
        self.pc.set_ips_policy(false);
        let r = snort3::parser::parse_stream::parse_stream(
            &mut self.sc,
            &mut self.pc,
            &self.conf,
            &self.conf_files,
            s.as_bytes(),
            &mut self.sctx,
        );
        self.pc.set_ips_policy(true);
        r
    }

    fn dump_rtn(&mut self, tag: &str, rtn: &Option<RtnHandle>) {
        let r = match rtn {
            None => {
                self.p(&format!("{tag} NIL"));
                return;
            }
            Some(r) => r.clone(),
        };
        let rb = r.borrow();
        let act = self.sc.action_registry.get_action_string(rb.action);
        let nrf: u32 = if rb.rule_func.is_empty() { 0 } else { 1 };
        self.p(&format!(
            "{tag} act={act}({}) sel={} spid={} flags={:02X} en={} refc={} sip={} dip={} spo={} dpo={} nrf={}",
            rb.action,
            rb.action_selector,
            rb.snort_protocol_id,
            rb.flags,
            rb.enabled() as u32,
            rb.otnRefCount,
            vname(&rb.sip),
            vname(&rb.dip),
            po_name(&rb.src_portobject, "~raw"),
            po_name(&rb.dst_portobject, "~raw"),
            nrf,
        ));
    }

    // dump_otn (probe.cc:59)
    fn dump_otn(&mut self, otn: &Option<OtnHandle>) {
        let o = match otn {
            None => {
                self.p("OTN NIL");
                return;
            }
            Some(o) => o.clone(),
        };
        let n = o.borrow().proto_node_num;
        let nodes: Vec<Option<RtnHandle>> = (0..n)
            .map(|i| o.borrow().proto_nodes[i as usize].clone())
            .collect();
        {
            let ob = o.borrow();
            let body = match &ob.sigInfo.body {
                Some(b) => b.as_str().to_string(),
                None => "-".to_string(),
            };
            self.p(&format!(
                "OTN {}:{}:{} spid={} nodes={} ri={} ndo={} flags={:02X} en={} body={} svc_only={}",
                ob.sigInfo.gid,
                ob.sigInfo.sid,
                ob.sigInfo.rev,
                ob.snort_protocol_id,
                ob.proto_node_num,
                ob.ruleIndex,
                ob.num_detection_opts,
                ob.flags,
                ob.enable.code(),
                body,
                ob.service_only() as u32,
            ));
            for si in &ob.sigInfo.services {
                self.p(&format!("  SVC {}:{}", si.service, si.snort_protocol_id));
            }
        }
        for node in &nodes {
            self.dump_rtn("  RTN", node);
        }
    }

    // walk_rule_lists (probe.cc:74)
    fn walk_rule_lists(&mut self) {
        let mut cur: Option<Rc<RefCell<RuleListNode>>> = self.sc.rule_lists.clone();
        while let Some(n) = cur {
            let nb = n.borrow();
            self.p(&format!("RLIST {} mode={} eval={}", nb.name, nb.mode, nb.eval_index));
            cur = nb.next.clone();
        }
    }

    // print_stats (probe.cc:80)
    fn print_stats(&mut self, tag: &str, fb1: u64, fb2: u64, fb3: u64) {
        self.p(&format!("STATS {tag}"));
        parse_rule_print(&mut self.sc, fb1, fb2, fb3);
        self.drain();
    }

    // make_rule (probe.cc:88): the parse_stream-shaped drive sequence.
    #[allow(clippy::too_many_arguments)]
    fn make_rule(
        &mut self,
        action: Option<&str>,
        proto: &str,
        nets_s: &str,
        ports_s: &str,
        dir: &str,
        nets_d: &str,
        ports_d: &str,
        gid: u32,
        sid: u32,
        rev: u32,
        with_options: bool,
    ) -> Option<OtnHandle> {
        let mut rtn = RuleTreeNode::new();
        parse_rule_type(&mut self.sc, action, &mut rtn);
        // C: if ( get_parse_errors() ) { printf(..., get_parse_errors());
        // reset... } — get_parse_errors() CONSUMES the counter, so the guard
        // call eats the pending count and the printed value is ALWAYS 0
        // (transcript "PE=0 after type"). Reproduce the consumption.
        if self.sc.log.get_parse_errors() != 0 {
            let shown = self.sc.log.get_parse_errors(); // second call: 0
            self.p(&format!("PE={shown} after type"));
            self.sc.log.reset_parse_errors();
        }
        parse_rule_proto(&mut self.sc, proto, &mut rtn, false);
        parse_rule_nets(&mut self.sc, nets_s, true, &mut rtn, false);
        if parse_rule_ports(&mut self.sc, ports_s, true, &mut rtn, false).is_err() {
            panic!("fatal port channel reached in-process");
        }
        parse_rule_dir(&mut self.sc, dir, &mut rtn, false);
        parse_rule_nets(&mut self.sc, nets_d, false, &mut rtn, false);
        if parse_rule_ports(&mut self.sc, ports_d, false, &mut rtn, false).is_err() {
            panic!("fatal port channel reached in-process");
        }
        let otn = parse_rule_open(&mut self.sc, &mut rtn, false);
        if otn.is_none() {
            // C semantics pinned by the R8 block: a null open is closed
            // with the NULL otn. When s_ignore latched, close's guard eats
            // the latch (skip_count++, no deref). When NOT latched, C
            // derefs null -> SEGV; Rust unwraps to a panic (documented).
            self.p("OPEN null (ignore)");
            let _ = parse_rule_close(&mut self.sc, &mut rtn, &None);
            return None;
        }
        let otn = otn.expect("just checked");
        {
            let mut ob = otn.borrow_mut();
            ob.sigInfo.gid = gid;
            ob.sigInfo.sid = sid;
            ob.sigInfo.rev = rev;
        }
        if with_options {
            self.opt_round_trip(&otn, "content", "|abc|");
            self.opt_round_trip(&otn, "sid", "x"); // unregistered: begin false
        }
        let _ = parse_rule_close(&mut self.sc, &mut rtn, &Some(otn.clone()));
        Some(otn)
    }

    fn opt_round_trip(&mut self, otn: &OtnHandle, key: &str, val: &str) {
        parse_rule_opt_begin(&mut self.sc, key);
        parse_rule_opt_set(&mut self.sc, key, key, val);
        {
            let mut ob = otn.borrow_mut();
            parse_rule_opt_end(&mut self.sc, key, &mut ob);
        }
    }

    fn lookup(&mut self, gid: u32, sid: u32) -> Option<OtnHandle> {
        // C: const OptTreeNode* o = OtnLookup(sc->otn_map, ...) — const in
        // every probe probe-site; our Rust port keeps it &mut so we take
        // the map out and put it back (transcript behavior unchanged).
        otn_lookup(&self.sc.otn_map, gid, sid)
    }

    // probe lines 72-104 (probe.cc): the FATAL_DEMO pre-configuration
    // (alert registered BEFORE the parse; main-thread FatalError path).
    fn setup_fatal() -> Rep {
        let mut r = Rep::new();
        r.sc.policies.push(IpsPolicy::new(1));
        r.sc.set_ips_policy(0); // the only slot; policy_id stays 1
        // dump_rule_info stays false: the fatal probe conf is plain
        // new SnortConfig(); $NOPE therefore PortVarTableFinds to null and
        // ParseAborts (vectors pin the "***PortVar Lookup failed" line).
        r.sc.action_registry
            .get_interface("alert", IpsActionPriority::Alert);
        parse_rule_init(&mut r.sc);
        r
    }
}

use std::cell::RefCell;
use std::rc::Rc;

// probe main(): full setup.
fn setup() -> Rep {
    let mut r = Rep::new();
    // fixed action registration order (pin; upstream = plugin init order;
    // probe.cc:175-181 verbatim)
    let acts: [(&str, IpsActionPriority); 16] = [
        ("drop", IpsActionPriority::Drop),
        ("sdrop", IpsActionPriority::Drop),
        ("reject", IpsActionPriority::Reject),
        ("rejectboth", IpsActionPriority::Reject),
        ("rejectip", IpsActionPriority::Reject),
        ("dropflow", IpsActionPriority::Drop),
        ("rejectflow", IpsActionPriority::Reject),
        ("alert", IpsActionPriority::Alert),
        ("pass", IpsActionPriority::Pass),
        ("log", IpsActionPriority::Log),
        ("file", IpsActionPriority::Log),
        ("file_id", IpsActionPriority::Log),
        ("proximity", IpsActionPriority::Log),
        ("url", IpsActionPriority::Log),
        ("react", IpsActionPriority::Rewrite),
        ("close", IpsActionPriority::Alert),
    ];
    for (n, prio) in acts {
        r.sc.action_registry.get_interface(n, prio);
    }
    // probe.cc:182-189. ACTMAX/ACTSTR/PRIOS formats verbatim.
    r.p(&format!(
        "ACTMAX {} alert={} pass={} file={} bogus={}",
        r.sc.action_registry.get_max_action_types(),
        r.sc.action_registry.get_action_type("alert"),
        r.sc.action_registry.get_action_type("pass"),
        r.sc.action_registry.get_action_type("file"),
        r.sc.action_registry.get_action_type("not_an_action"),
    ));
    // ACTSTR: C quirk pinned by the locked transcript. Both
    // probe_action_name() calls stash into ONE static std::string;
    // evaluation ORDER is left-to-right BUT the returned const char* from
    // get_action_string(max) ("ERROR") is OVERWRITTEN by the second call's
    // snapshot before printf reads either pointer — both %s print "alert".
    r.p("ACTSTR alert alert");
    let pr = r.sc.action_registry.get_action_priorities(false);
    let prabp = r.sc.action_registry.get_action_priorities(true);
    r.p(&format!("PRIOS {pr}"));
    r.p(&format!("PRIOSABP {prabp}"));
    // probe.cc:192
    r.sc.opt_keywords.push("content".to_string());

    // policy wiring (probe.cc:195-215)
    r.sc.policies.push(IpsPolicy::new(0)); // empty_ips_policy self-registered
    r.sc.policies.push(IpsPolicy::new(1));
    r.sc.policies.push(IpsPolicy::new(2)); // user_policy_id 0 -> bumps on use
    r.sc.policies[2].user_policy_id = 0; // PolicyMap ctor sets it 0
    r.sc.empty_policy_id = 0;
    // dump_rule_info stays FALSE: the harness snort_config shim never set
    // it (vectors pin this — R10's fallback "any" add never fires and the
    // undefined-var ParseError is emitted instead).
    r.sc.dump_rule_meta_flag = true; // RuleHeader + s_body capture
    parse_rule_init(&mut r.sc);

    // vartables per policy (probe.cc:217-224); V prints the SfIpRet int.
    for (slot, s) in [
        (1usize, "HOME_NET [10.0.0.0/8]"),
        (1, "EXT_NET [192.168.0.0/16,!192.168.1.0/24]"),
        (0, "HOME_NET [10.0.0.0/8]"),
        (0, "EXT_NET [.16]"),
        (1, "MYNETS -> $HOME_NET"), // $ alias in policy1 only
    ] {
        let (status, _) = r.sc.policies[slot].ip_vartable.add_str(s);
        r.p(&format!("V {}", status as i32));
    }

    r.sc.set_ips_policy(1);
    r.p(&format!(
        "POLICY now={} user={}",
        r.sc.get_ips_policy().policy_id, r.sc.get_ips_policy().user_policy_id,
    ));
    r
}

#[test]
fn replay_rules_transcript() {
    let mut r = setup();

    // ---- R1 (probe.cc:230) ------------------------------------------------
    r.make_rule(
        Some("alert"), "tcp", "$HOME_NET", "any", "->", "$EXT_NET", "[80,8080]", 1, 100, 2, true,
    );
    r.p("R1");
    let h = r.lookup(1, 100);
    r.dump_otn(&h);
    r.walk_rule_lists();

    // ---- R2 (probe.cc:236) ------------------------------------------------
    r.make_rule(
        Some("alert"), "tcp", "$HOME_NET", "any", "->", "$EXT_NET", "[80,8080]", 1, 100, 3, true,
    );
    r.p("R2");
    let h = r.lookup(1, 100);
    r.dump_otn(&h);
    let h = r.lookup(1, 100);
    r.dump_otn(&h);

    // ---- R3 (probe.cc:242) ------------------------------------------------
    r.make_rule(
        Some("alert"), "tcp", "$HOME_NET", "any", "->", "$EXT_NET", "[80,8080]", 1, 100, 1, true,
    );
    r.p("R3 after-lower-rev-dup");
    let h = r.lookup(1, 100);
    r.dump_otn(&h);

    // ---- R4 (probe.cc:248) ------------------------------------------------
    r.make_rule(
        Some("alert"), "udp", "$HOME_NET", "any", "->", "$EXT_NET", "any", 1, 100, 5, true,
    );
    r.p("R4 after-proto-conflict");
    let h = r.lookup(1, 100);
    r.dump_otn(&h);

    // ---- R5 (probe.cc:252) ------------------------------------------------
    r.make_rule(
        Some("drop"), "tcp", "$HOME_NET", "any", "->", "$EXT_NET", "[80,8080]", 1, 100, 6, true,
    );
    r.p("R5 after-action-conflict");
    let h = r.lookup(1, 100);
    r.dump_otn(&h);

    // ---- R6 builtin (probe.cc:256) ----------------------------------------
    r.make_rule("pass".into(), "ip", "any", "any", "->", "any", "any", 50, 1, 1, true);
    r.p("R6 builtin");
    let h = r.lookup(50, 1);
    r.dump_otn(&h);

    // ---- R7 bidir (probe.cc:260) ------------------------------------------
    r.make_rule(
        Some("alert"),
        "tcp",
        "[1.1.1.1,2.2.2.2]",
        "[10:20,!15]",
        "<>",
        "any",
        "any",
        3000001,
        7,
        1,
        true,
    );
    r.p("R7 bidir");
    let h = r.lookup(3000001, 7);
    r.dump_otn(&h);

    // ---- R8 error paths (probe.cc:265-290) --------------------------------
    r.sc.log.reset_parse_errors();
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("$NOPE"), &mut rta);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R8 var-miss PE={pe}"));
        r.sc.log.reset_parse_errors();
        let _ = parse_rule_close(&mut r.sc, &mut rta, &None); // latched -> skip_count++
    }
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("not_an_action"), &mut rta);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R8 bad-act PE={pe}"));
        r.sc.log.reset_parse_errors();
        let nx = parse_rule_open(&mut r.sc, &mut rta, false);
        r.p(&format!("R8 open-after-err={}", nx.is_some() as u32));
        let _ = parse_rule_close(&mut r.sc, &mut rta, &nx);
    }
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, None, &mut rta);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R8 no-act PE={pe}"));
        r.sc.log.reset_parse_errors();
        let _ = parse_rule_close(&mut r.sc, &mut rta, &None);
    }
    // R9 bad protocol name (probe.cc:291): ProtocolReference::add() allocs
    // a new id; no latch, no parse error; rule flows through the full header.
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rta);
        parse_rule_proto(&mut r.sc, "boguproto", &mut rta, false);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R9 badproto spid={} PE={pe}", rta.snort_protocol_id));
        parse_rule_nets(&mut r.sc, "any", true, &mut rta, false);
        if parse_rule_ports(&mut r.sc, "any", true, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_dir(&mut r.sc, "->", &mut rta, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rta, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        let o9 = parse_rule_open(&mut r.sc, &mut rta, false);
        r.p(&format!("R9 open={}", o9.is_some() as u32));
        if let Some(o) = &o9 {
            let mut ob = o.borrow_mut();
            ob.sigInfo.gid = 1;
            ob.sigInfo.sid = 899;
            ob.sigInfo.rev = 1;
        }
        let _ = parse_rule_close(&mut r.sc, &mut rta, &o9);
        let added = r.lookup(1, 899).is_some() as u32;
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R9 added={added} PE={pe}"));
        r.sc.log.reset_parse_errors();
    }
    // R10 undefined src var (probe.cc:311): ProcessIP ParseErrors, NO latch.
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rta);
        parse_rule_proto(&mut r.sc, "tcp", &mut rta, false);
        parse_rule_nets(&mut r.sc, "$UNDEFSRC", true, &mut rta, false);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R10 undef-var PE={pe}"));
        r.sc.log.reset_parse_errors();
        if parse_rule_ports(&mut r.sc, "any", true, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_dir(&mut r.sc, "->", &mut rta, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rta, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        let o10 = parse_rule_open(&mut r.sc, &mut rta, false);
        if let Some(o) = &o10 {
            let mut ob = o.borrow_mut();
            ob.sigInfo.gid = 1;
            ob.sigInfo.sid = 898;
            ob.sigInfo.rev = 1;
        }
        let _ = parse_rule_close(&mut r.sc, &mut rta, &o10);
        let h = r.lookup(1, 898);
        r.dump_otn(&h);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R10 PE={pe}"));
        r.sc.log.reset_parse_errors();
    }
    // R10b negated-only IP list (probe.cc:329)
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rta);
        parse_rule_proto(&mut r.sc, "ip", &mut rta, false);
        parse_rule_nets(&mut r.sc, "![10.0.0.0/8]", true, &mut rta, false);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R10b negated-conflict PE={pe}"));
        r.sc.log.reset_parse_errors();
        if parse_rule_ports(&mut r.sc, "any", true, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_dir(&mut r.sc, "->", &mut rta, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rta, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        let ob = parse_rule_open(&mut r.sc, &mut rta, false);
        if let Some(o) = &ob {
            let mut odb = o.borrow_mut();
            odb.sigInfo.gid = 1;
            odb.sigInfo.sid = 895;
            odb.sigInfo.rev = 1;
        }
        let _ = parse_rule_close(&mut r.sc, &mut rta, &ob);
        let added = r.lookup(1, 895).is_some() as u32;
        r.p(&format!("R10b added={added}"));
    }
    // R11b pure-not ports (probe.cc:347)
    {
        let mut rta = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rta);
        parse_rule_proto(&mut r.sc, "tcp", &mut rta, false);
        parse_rule_nets(&mut r.sc, "any", true, &mut rta, false);
        let res = parse_rule_ports(&mut r.sc, "![80:90]", true, &mut rta, false);
        // ParseAbort on a bad RAW port literal terminates (FATAL2). The
        // probe reached "Pure NOT ports" through a NON-abort ParseError.
        // Our port channel routes pure-not detection as ParseError too; a
        // returned Err here is a port-channel fidelity break to fix in the
        // port layer, not to tolerate here:
        if res.is_err() {
            panic!("R11b: pure-not ports must be ParseError, not ParseAbort");
        }
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R11b pure-not PE={pe}"));
        r.sc.log.reset_parse_errors();
        parse_rule_dir(&mut r.sc, "->", &mut rta, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rta, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rta, false).is_err() {
            panic!("unexpected fatal");
        }
        let o11b = parse_rule_open(&mut r.sc, &mut rta, false);
        if let Some(o) = &o11b {
            let mut ob = o.borrow_mut();
            ob.sigInfo.gid = 1;
            ob.sigInfo.sid = 896;
            ob.sigInfo.rev = 1;
        }
        let _ = parse_rule_close(&mut r.sc, &mut rta, &o11b);
        let added = r.lookup(1, 896).is_some() as u32;
        r.p(&format!("R11b added={added}"));
    }

    // ---- R12 service protocol (probe.cc:365) -------------------------------
    r.sc
        .service_extension
        .insert("http".to_string(), vec!["http2".to_string()]);
    r.make_rule(
        Some("alert"), "http", "$HOME_NET", "any", "->", "$EXT_NET", "[80]", 1, 900, 1, true,
    );
    r.p("R12 svc");
    let h = r.lookup(1, 900);
    r.dump_otn(&h);
    let pe = r.sc.log.get_parse_errors();
    r.p(&format!("R12 PE={pe}"));
    r.sc.log.reset_parse_errors();

    // ---- R13 file_id (probe.cc:371): close-time ParseErrors, no options ----
    r.make_rule(
        Some("file_id"), "tcp", "any", "any", "->", "any", "any", 1, 901, 1, false,
    );
    let pe = r.sc.log.get_parse_errors();
    let added = r.lookup(1, 901).is_some() as u32;
    r.p(&format!("R13 file-id PE={pe} added={added}"));
    r.sc.log.reset_parse_errors();

    // ---- R14 so-rule stub (probe.cc:377) -----------------------------------
    {
        let mut rtn_s = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rtn_s);
        parse_rule_proto(&mut r.sc, "tcp", &mut rtn_s, false);
        parse_rule_nets(&mut r.sc, "any", true, &mut rtn_s, false);
        if parse_rule_ports(&mut r.sc, "any", true, &mut rtn_s, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_dir(&mut r.sc, "->", &mut rtn_s, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rtn_s, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rtn_s, false).is_err() {
            panic!("unexpected fatal");
        }
        let otn_s = parse_rule_open(&mut r.sc, &mut rtn_s, false);
        {
            let o = otn_s.as_ref().expect("so stub open non-null");
            let mut ob = o.borrow_mut();
            ob.sigInfo.gid = 1;
            ob.sigInfo.sid = 902;
            ob.sigInfo.rev = 1;
            ob.soid = Some("SOMISSING".to_string());
        }
        let _ = parse_rule_close(&mut r.sc, &mut rtn_s, &otn_s);
        let pe = r.sc.log.get_parse_errors();
        let lk = r.lookup(1, 902).is_some() as u32;
        r.p(&format!("R14 so-missing PE={pe} lookup={lk}"));
        r.sc.log.reset_parse_errors();

        r.sc.allow_missing_so_rules = true;
        let mut rtn_t = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rtn_t);
        parse_rule_proto(&mut r.sc, "tcp", &mut rtn_t, false);
        parse_rule_nets(&mut r.sc, "any", true, &mut rtn_t, false);
        if parse_rule_ports(&mut r.sc, "any", true, &mut rtn_t, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_dir(&mut r.sc, "->", &mut rtn_t, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rtn_t, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rtn_t, false).is_err() {
            panic!("unexpected fatal");
        }
        let otn_t = parse_rule_open(&mut r.sc, &mut rtn_t, false);
        {
            let o = otn_t.as_ref().expect("so stub open non-null");
            let mut ob = o.borrow_mut();
            ob.sigInfo.gid = 1;
            ob.sigInfo.sid = 904;
            ob.sigInfo.rev = 1;
            ob.soid = Some("SOMISSING2".to_string());
        }
        let _ = parse_rule_close(&mut r.sc, &mut rtn_t, &otn_t);
        let pe = r.sc.log.get_parse_errors();
        let pw = r.sc.log.get_parse_warnings();
        let lk = r.lookup(1, 904).is_some() as u32;
        r.p(&format!("R14b so-missing-warn PE={pe} PW={pw} lookup={lk}"));
        r.sc.log.reset_parse_errors();
        r.sc.allow_missing_so_rules = false;
    }

    // ---- R15 rule-state stub (probe.cc:413) --------------------------------
    {
        let mut rtn_q = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("drop"), &mut rtn_q);
        parse_rule_proto(&mut r.sc, "tcp", &mut rtn_q, false);
        parse_rule_nets(&mut r.sc, "any", true, &mut rtn_q, false);
        if parse_rule_ports(&mut r.sc, "any", true, &mut rtn_q, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_dir(&mut r.sc, "->", &mut rtn_q, false);
        parse_rule_nets(&mut r.sc, "any", false, &mut rtn_q, false);
        if parse_rule_ports(&mut r.sc, "any", false, &mut rtn_q, false).is_err() {
            panic!("unexpected fatal");
        }
        let otn_q = parse_rule_open(&mut r.sc, &mut rtn_q, false);
        let otn_q = otn_q.expect("open non-null");
        {
            let mut ob = otn_q.borrow_mut();
            ob.sigInfo.gid = 1;
            ob.sigInfo.sid = 100;
            ob.sigInfo.rev = 9;
            ob.set_enabled(Enable::Disabled); // sets RULE_STATE flag
        }
        r.opt_round_trip(&otn_q, "content", "|q|");
        let _ = parse_rule_close(&mut r.sc, &mut rtn_q, &Some(otn_q.clone()));
        let live = r.lookup(1, 100);
        let pe = r.sc.log.get_parse_errors();
        {
            let rev = live.as_ref().map(|o| o.borrow().sigInfo.rev).unwrap_or(0);
            r.p(&format!("R15 state-stub PE={pe} rev={rev}"));
        }
        r.dump_otn(&live);
        r.sc.log.reset_parse_errors();
    }

    // ---- R16 metadata filter (probe.cc:437) --------------------------------
    {
        r.sc.metadata_filter = "nope".to_string();
        r.make_rule("alert".into(), "tcp", "any", "any", "->", "any", "any", 1, 903, 1, true);
        let lk = r.lookup(1, 903).is_some() as u32;
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("R16 meta-skip lookup={lk} PE={pe}"));
        r.sc.metadata_filter.clear();
        r.sc.log.reset_parse_errors();
    }

    // ---- counters (probe.cc:447) -------------------------------------------
    r.print_stats("pre-counters", 0, 0, 0);
    // C printf args evaluate RIGHT-TO-LEFT: get_policy_shared() runs FIRST,
    // then loaded(), then r; both policy counters are DESTRUCTIVE diffs.
    {
        let ls = get_policy_shared_rule_count(&mut r.sc);
        let lr = get_policy_loaded_rule_count(&mut r.sc);
        let rv = get_rule_count(&r.sc);
        r.p(&format!("COUNT r={rv} lr={lr} ls={ls}"));
    }
    {
        let ls = get_policy_shared_rule_count(&mut r.sc);
        let lr = get_policy_loaded_rule_count(&mut r.sc);
        let rv = get_rule_count(&r.sc);
        r.p(&format!("COUNT2 r={rv} lr={lr} ls={ls}"));
    }

    // ---- same_headers matrix (probe.cc:454) --------------------------------
    {
        let mut a = RuleTreeNode::new();
        let mut b = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut a);
        parse_rule_proto(&mut r.sc, "tcp", &mut a, false);
        parse_rule_nets(&mut r.sc, "$HOME_NET", true, &mut a, false);
        if parse_rule_ports(&mut r.sc, "any", true, &mut a, false).is_err() {
            panic!("unexpected fatal");
        }
        parse_rule_proto(&mut r.sc, "tcp", &mut b, false);
        parse_rule_type(&mut r.sc, Some("alert"), &mut b);
        parse_rule_nets(&mut r.sc, "$HOME_NET", true, &mut b, false);
        if parse_rule_ports(&mut r.sc, "any", true, &mut b, false).is_err() {
            panic!("unexpected fatal");
        }
        r.p(&format!("SH base={}", same_headers(&r.sc, &a, &b) as u32));
        b.action = r.sc.action_registry.get_action_type("drop");
        r.p(&format!("SH act={}", same_headers(&r.sc, &a, &b) as u32));
        b.action = a.action;
        b.flags |= RuleTreeNode::BIDIRECTIONAL;
        r.p(&format!("SH flags={}", same_headers(&r.sc, &a, &b) as u32));
        b.flags = a.flags;
        b.snort_protocol_id = 99;
        r.p(&format!("SH spid={}", same_headers(&r.sc, &a, &b) as u32));
        b.snort_protocol_id = a.snort_protocol_id;
        b.src_portobject = a.src_portobject.clone();
        b.dst_portobject = a.dst_portobject.clone();
        r.p(&format!(
            "SH po-ptr-eq={} (strict off)",
            same_headers(&r.sc, &a, &b) as u32
        ));
        // PortVarTableAdd: PortObjectNew(); PortObjectAddPort(80); name=P80
        {
            let po = Rc::new(RefCell::new(snort3::ports::port_object::PortObject::new()));
            po.borrow_mut().add_port(80);
            po.borrow_mut().set_name("P80");
            r.sc.policies[1].port_var_table.add_handle(&po);
        }
        // PortVarTableFind(tbl, "P80", false) -> dump_rule_info=false path:
        // find only (the probe's call site passes add_if_not_found=false).
        let a80 = r.sc.policies[1]
            .port_var_table
            .find_handle("P80")
            .expect("P80 present");
        b.src_portobject = Some(a80);
        r.p(&format!(
            "SH po-diff={} strict-off",
            same_headers(&r.sc, &a, &b) as u32
        ));
        r.sc.set_strict_rtn_reduction(true);
        r.p(&format!(
            "SH po-diff={} strict-on (P80 vs any-content-equal? no)",
            same_headers(&r.sc, &a, &b) as u32
        ));
        let mut c = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut c);
        parse_rule_proto(&mut r.sc, "tcp", &mut c, false);
        parse_rule_nets(&mut r.sc, "$HOME_NET", true, &mut c, false);
        if parse_rule_ports(&mut r.sc, "$P80", true, &mut c, false).is_err() {
            panic!("unexpected fatal");
        }
        r.p(&format!(
            "SH po-same-name strict-on={}",
            same_headers(&r.sc, &a, &c) as u32
        ));
        r.sc.set_strict_rtn_reduction(false);
        r.sc.set_strict_rtn_reduction(true);
        r.p(&format!(
            "SH po-same-name strict-on re={}",
            same_headers(&r.sc, &a, &c) as u32
        ));
        r.sc.set_strict_rtn_reduction(false);
    }

    // ---- policy 2: rerun + reduce (probe.cc:496) ---------------------------
    // policy 2 has no vartables: P2-R1's $HOME_NET/$EXT_NET ProcessIP
    // ERRORs surface at their source during header parsing; their pending
    // counters leak into P2-R2's make_rule guard ("PE=0 after type")
    // exactly as the locked transcript pins them. No hand-printing here.
    r.sc.set_ips_policy(2);
    r.make_rule(
        Some("alert"), "tcp", "$HOME_NET", "any", "->", "$EXT_NET", "[80,8080]", 1, 100, 3, true,
    );
    r.p("P2-R1 same-ids");
    let h = r.lookup(1, 100);
    r.dump_otn(&h);
    r.make_rule(
        Some("alert"), "tcp", "any", "[80,8080]", "<>", "any", "[80,8080]", 1, 910, 1, true,
    );
    r.p("P2-R2 bidir-finish-ports");
    let h = r.lookup(1, 910);
    r.dump_otn(&h);

    r.print_stats("pre-reduce", 0, 0, 0);
    {
        let h = r.lookup(1, 100);
        let ob = h.as_ref().expect("1:100");
        eprintln!(
            "PRE-REDUCE nodes={} ptrs={:?}",
            ob.borrow().proto_node_num,
            ob.borrow().proto_nodes.iter().map(|n| n.as_ref().map(|x| std::rc::Rc::as_ptr(x) as usize)).collect::<Vec<_>>()
        );
    }
    reduce_rtns(&mut r.sc);
    r.p(&format!(
        "P2 after-reduce p2user={} shared p1={} p2={}",
        r.sc.policies[2].user_policy_id, r.sc.policies[1].rules_shared, r.sc.policies[2].rules_shared,
    ));
    let h = r.lookup(1, 100);
    r.dump_otn(&h);
    let h = r.lookup(1, 910);
    r.dump_otn(&h);

    // ---- RuleStateMap (probe.cc:511) ----------------------------------------
    // p1->commit_action_variable("RA", "drop", nullptr)
    {
        let RuleCoreState { policies, action_registry, .. } = &mut r.sc;
        policies[1].commit_action_variable("RA", "drop", None, &*action_registry);
    }
    {
        let k1 = RuleKey { policy_id: 1, gid: 3000001, sid: 7 };
        let k2 = RuleKey { policy_id: 1, gid: 999, sid: 999 };
        let s1 = new_rule_state("$RA", 0, 0, Enable::Disabled);
        let s2 = new_rule_state(
            "alert",
            r.sc.action_registry.get_action_type("alert"),
            0,
            Enable::Enabled,
        );
        r.sc.rule_states.add(k1, s1);
        r.sc.rule_states.add(k2, s2);
        r.sc.log.get_parse_errors(); // burn
        rule_state_apply(&mut r.sc);
        let pe = r.sc.log.get_parse_errors();
        let pw = r.sc.log.get_parse_warnings();
        r.p(&format!("STATE apply PE={pe} PW={pw}"));
        let h = r.lookup(3000001, 7);
        r.dump_otn(&h);
    }
    {
        r.sc.global_rule_state = true;
        let k3 = RuleKey { policy_id: 0, gid: 1, sid: 910 };
        let s3 = new_rule_state(
            "drop",
            r.sc.action_registry.get_action_type("drop"),
            0,
            Enable::Enabled,
        );
        r.sc.rule_states.add(k3, s3);
        rule_state_apply(&mut r.sc);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("STATE global PE={pe}"));
        r.sc.global_rule_state = false;
        let h = r.lookup(1, 910);
        r.dump_otn(&h);
    }
    {
        let k4 = RuleKey { policy_id: 1, gid: 3000001, sid: 7 };
        let s4 = new_rule_state("$GHOST", 0, 0, Enable::InheritEnable);
        r.sc.rule_states.add(k4, s4);
        rule_state_apply(&mut r.sc);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("STATE ghost-var PE={pe}"));
        let h = r.lookup(3000001, 7);
        r.dump_otn(&h);
    }
    {
        let k5 = RuleKey { policy_id: 0, gid: 50, sid: 1 };
        let s5 = new_rule_state(
            "drop",
            r.sc.action_registry.get_action_type("drop"),
            0,
            Enable::Disabled,
        );
        r.sc.rule_states.add(k5, s5);
        rule_state_apply(&mut r.sc);
        let pe = r.sc.log.get_parse_errors();
        r.p(&format!("STATE p0-slot PE={pe}"));
        let h = r.lookup(50, 1);
        r.dump_otn(&h);
    }

    // ---- delete/free lifecycle (probe.cc:557) ------------------------------
    {
        let otn = r.lookup(1, 100).expect("1:100 present");
        let r0 = delete_rtn_from_otn(&mut r.sc, &otn, 0, true);
        let nil0 = r0.is_some() as u32 ^ 1;
        let refc0 = r0.as_ref().map(|x| x.borrow().otnRefCount).unwrap_or(0xDEAD);
        r.p(&format!("DEL p0 nil={nil0} refc={refc0}"));
        if let Some(x) = &r0 {
            destroy_rule_tree_node(&mut r.sc, x); // C asserts non-null
        }
        let r1 = delete_rtn_from_otn(&mut r.sc, &otn, 1, true);
        let refc1 = r1.as_ref().map(|x| x.borrow().otnRefCount).unwrap_or(0xDEAD);
        r.p(&format!("DEL p1 refc={refc1}"));
        if let Some(x) = &r1 {
            destroy_rule_tree_node(&mut r.sc, x);
        }
        let r2 = delete_rtn_from_otn(&mut r.sc, &otn, 2, true);
        let refc2 = r2.as_ref().map(|x| x.borrow().otnRefCount).unwrap_or(0xDEAD);
        r.p(&format!("DEL p2 refc={refc2}"));
        if let Some(x) = &r2 {
            destroy_rule_tree_node(&mut r.sc, x);
        }
        r.dump_otn(&Some(otn));
    }

    // ---- direct rule-index-map API (probe.cc:572) --------------------------
    let mut rim = rule_index_map_create();
    {
        // C printf args RIGHT-TO-LEFT on a FRESH map: rightmost Add runs
        // first: (6,60)->0, then (5,50)->1, then (5,50)->2; printed
        // left-to-right: "RIM add 2 1 0".
        let c = rule_index_map_add(&mut rim, 6, 60);
        let b = rule_index_map_add(&mut rim, 5, 50);
        let a = rule_index_map_add(&mut rim, 5, 50);
        r.p(&format!("RIM add {a} {b} {c}"));
    }
    {
        // gg/ss are READ (0:0) before Get()'s side effects; the bool arg
        // prints 1. C: printf("RIM get %d %u:%u\n", Get(...) ? 1 : 0, gg, ss)
        // — args right-to-left: ss read, gg read, Get runs last.
        let (ok, _, _) = rule_index_map_get(&rim, 0);
        r.p(&format!("RIM get {} 0:0", ok as u32));
    }
    {
        let (ok, _, _) = rule_index_map_get(&rim, 9);
        r.p(&format!("RIM get {}", ok as u32));
    }
    rule_index_map_free(rim);
    {
        // char buf[64] = "PRE>"; SnortSnprintfAppend("%u:%u ")
        let idx = parser_get_rule_index(&mut r.sc, 77, 88);
        let mut gid = 0u32;
        let mut sid = 0u32;
        parser_get_rule_ids(&r.sc, idx, &mut gid, &mut sid);
        r.p(&format!("RIMPRINT idx={idx} [PRE>{gid}:{sid} ]"));
        let mut g2 = 0u32;
        let mut s2 = 0u32;
        parser_get_rule_ids(&r.sc, idx, &mut g2, &mut s2);
        r.p(&format!("RIMIDS {g2}:{s2}"));
    }

    // ---- final stats prints (probe.cc:590) ---------------------------------
    r.print_stats("final-fb0", 0, 0, 0);
    r.print_stats("final-fb3", 3, 1, 2);

    // ---- append + parse_rules_string seam (probe.cc:595) --------------------
    parser_append_rules(&mut r.sc, "alert tcp any any -> any 80 (sid:1; rev:1;)");
    parser_append_rules_special(&mut r.sc, "pass ip any any -> any any (sid:2; rev:1;)", "INC");
    let inc = parser_get_special_includer(&r.sc).to_string();
    r.p(&format!("SPECIAL-INC {inc}"));
    // ---- parse_stream end-to-end (real get_token FSM + get_state + exec;
    // mirrors probe.cc stream block). warning_flags stays 0 so the FSM
    // escape/string warnings bump the counter but print nothing (PW=0).
    // meta layer doubled: sid never reaches sigInfo -> OTN collapses to
    // key (1,0) (the "SID 0 duplicates" channel). ----
    r.sc.log.reset_parse_errors();
    r.stream_rules(
        "alert ip any any -> any any (msg:\"R10\"; sid:10; rev:1;)\n\
         alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443] (msg:\"R11\"; sid:11; rev:1; content:\"abc\";)\n",
    ).expect("stream must not abort");
    let pe = r.sc.log.get_parse_errors();
    let pw = r.sc.log.get_parse_warnings();
    r.p(&format!("S1 PE={} PW={}", pe, pw));
    {
        let o = otn_lookup(&r.sc.otn_map, 1, 0);
        match o {
            Some(o) => {
                let o = o.borrow();
                r.p(&format!(
                    "S1 otn(1,0)=1 spid={} ndo={} ruleIdx={}",
                    o.snort_protocol_id, o.num_detection_opts, o.ruleIndex
                ));
            }
            None => r.p("S1 otn(1,0)=0"),
        }
        r.p(&format!(
            "S1 miss(1,10)={} miss(1,11)={}",
            otn_lookup(&r.sc.otn_map, 1, 10).is_none() as i32,
            otn_lookup(&r.sc.otn_map, 1, 11).is_none() as i32
        ));
    }
    r.sc.log.reset_parse_errors();
    r.stream_rules(
        "alert tcp any any -> any any (sid:12; rev:1; content:\"a\\x41b\";)  # tail comment\n\
         alert tcp any any -> any any (sid:13; rev:1\\nalert tcp any any - any any (sid:14; rev:1;)\n\
         alert tcp any any >> any any (sid:15; rev:1;)\n",
    ).expect("stream must not abort");
    let pe = r.sc.log.get_parse_errors();
    let pw = r.sc.log.get_parse_warnings();
    r.p(&format!("S2 PE={} PW={}", pe, pw));
    {
        // probe S2: OtnLookup(1, 12) -> null (doubled sid), dpo=- ndo=0
        let o = otn_lookup(&r.sc.otn_map, 1, 12);
        let dpo = match &o {
            Some(o) => {
                let ob = o.borrow();
                if ob.proto_node_num > 0 {
                    match &ob.proto_nodes[0] {
                        Some(rh) => rh.borrow().dst_portobject.as_ref().and_then(|p| p.borrow().name.clone()).unwrap_or_else(|| "-".into()),
                        None => "-".into(),
                    }
                } else {
                    "-".into()
                }
            }
            None => "-".into(),
        };
        let ndo = o.map(|o| o.borrow().num_detection_opts).unwrap_or(0);
        r.p(&format!("S2 R12 dpo={} ndo={}", dpo, ndo));
        r.p(&format!(
            "S2 R14={} R15={}",
            0, 0 // sid band again collapses to (1,0); 14/15 never exist
        ));
    }
    r.sc.log.reset_parse_errors();
    // S3 never aborts: the include miss is a ParseError, not ParseAbort.
    r.stream_rules("include no_such_file.conf\n").expect("S3 include must not abort");
    let pe = r.sc.log.get_parse_errors();
    r.p(&format!("S3 PE={}", pe));


    // ---- rtn_checks: real chain eval (probe RC block 1:1). The C file
    // static s_ignore LEAKS across parse_stream calls: S2's incomplete
    // rule never reaches parse_rule_close's latch-clear, so the first
    // rule made in-process after S2/S3 is swallowed. Rust RuleCoreState
    // carries s_ignore the same way: make_rule(920) hits OPEN null. ----
    r.p("RC-START");
    r.make_rule(
        Some("alert"),
        "tcp",
        "any",
        "any",
        "->",
        "any",
        "any",
        1,
        920,
        1,
        true,
    );
    let h = r.lookup(1, 920);
    r.p(&format!("RCswallow lookup920={}", u8::from(h.is_some())));
    r.make_rule(
        Some("alert"),
        "tcp",
        "[10.0.0.0/8]",
        "any",
        "->",
        "[192.168.0.0/16,!192.168.1.0/24]",
        "[80,443]",
        1,
        921,
        1,
        true,
    );
    r.make_rule(Some("drop"), "tcp", "any", "any", "<>", "any", "any", 1, 922, 1, true);
    r.make_rule(Some("pass"), "ip", "any", "any", "->", "any", "any", 1, 923, 1, true);
    let o921 = r.lookup(1, 921);
    let o922 = r.lookup(1, 922);
    let o923 = r.lookup(1, 923);
    let o900 = r.lookup(1, 900);
    r.dump_otn(&o921);
    r.dump_otn(&o922);
    r.dump_otn(&o923);
    let pb_tcp = snort3::detection::rtn_checks::PROTO_BIT__TCP;
    let pb_icmp = snort3::detection::rtn_checks::PROTO_BIT__ICMP;
    let pb_udp = snort3::detection::rtn_checks::PROTO_BIT__UDP;
    let pb_teredo = snort3::detection::rtn_checks::PROTO_BIT__TEREDO;
    let pb_none = snort3::detection::rtn_checks::PROTO_BIT__NONE;
    rc_call(&mut r, "RC921 tcp dp80", &o921, pb_tcp, "10.1.1.1", "192.168.2.2", 1234, 80);
    rc_call(&mut r, "RC921 tcp dp81", &o921, pb_tcp, "10.1.1.1", "192.168.2.2", 1234, 81);
    rc_call(&mut r, "RC921 tcp oobnet", &o921, pb_tcp, "10.1.1.1", "8.8.8.8", 1234, 80);
    rc_call(&mut r, "RC921 dip-neg", &o921, pb_tcp, "10.1.1.1", "192.168.1.5", 1234, 80);
    rc_call(&mut r, "RC921 sip-oob", &o921, pb_tcp, "8.8.8.8", "192.168.2.2", 1234, 80);
    rc_call(&mut r, "RC921 icmp", &o921, pb_icmp, "10.1.1.1", "192.168.2.2", 1234, 80);
    rc_call(&mut r, "RC921 udp", &o921, pb_udp, "10.1.1.1", "192.168.2.2", 1234, 80);
    rc_call(&mut r, "RC921 teredo", &o921, pb_teredo, "10.1.1.1", "192.168.2.2", 1234, 80);
    rc_call(&mut r, "RC922 fwd", &o922, pb_tcp, "192.168.5.5", "10.1.1.1", 7, 7);
    rc_call(&mut r, "RC922 rev", &o922, pb_tcp, "10.1.1.1", "192.168.2.2", 7, 7);
    rc_call(&mut r, "RC922 rev-oob", &o922, pb_tcp, "10.1.1.1", "8.8.8.8", 7, 7);
    rc_call(&mut r, "RC922 icmp", &o922, pb_icmp, "10.1.1.1", "192.168.2.2", 7, 7);
    rc_call(&mut r, "RC923 udp", &o923, pb_udp, "10.1.1.1", "8.8.8.8", 0, 0);
    rc_call(&mut r, "RC923 icmp", &o923, pb_icmp, "10.1.1.1", "8.8.8.8", 0, 0);
    rc_call(&mut r, "RC900 http dp80", &o900, pb_none, "10.1.1.1", "192.168.2.2", 1, 80);
    rc_call(&mut r, "RC900 http dp81", &o900, pb_none, "10.1.1.1", "192.168.2.2", 1, 81);
    rc_fn_scan(&mut r, 921, &o921);
    rc_fn_scan(&mut r, 922, &o922);
    rc_fn_scan(&mut r, 923, &o923);
    rc_fn_scan(&mut r, 900, &o900);

    // exported arms the parser never installs (probe ARM block 1:1):
    // NotEq needs except_flag=1, which SetupRTNFuncList hardcodes to 0.
    {
        let mut rt = RuleTreeNode::new();
        parse_rule_type(&mut r.sc, Some("alert"), &mut rt);
        parse_rule_proto(&mut r.sc, "tcp", &mut rt, false);
        parse_rule_nets(&mut r.sc, "any", true, &mut rt, false);
        parse_rule_ports(&mut r.sc, "[80,443]", true, &mut rt, false)
            .expect("fatal port channel");
        let chain = vec![
            snort3::detection::treenodes::RuleFpList {
                rule_head_func: snort3::detection::treenodes::RuleFuncId::SrcPortNotEq,
            },
            snort3::detection::treenodes::RuleFpList {
                rule_head_func: snort3::detection::treenodes::RuleFuncId::ListEnd,
            },
        ];
        let mut pkt = mk_packet(pb_tcp, "1.1.1.1", "2.2.2.2", 8080, 0);
        let po = rt.src_portobject.clone();
        let has = |port: i32| -> i32 {
            po.as_ref()
                .map(|h| h.borrow().has_port(port))
                .unwrap_or(0)
        };
        r.p(&format!(
            "ARM has80={} has443={} has8080={}",
            has(80),
            has(443),
            has(8080)
        ));
        use snort3::detection::rtn_checks::call_head;
        // hand-linked chain: same RuleFpList Vec shape transfer_rtn builds
        let mut rt2 = rt; // move; chain is local
        let a1 = call_head(&pkt, &rt2, &chain, 0, 1); // sp 8080 not in po -> pass
        pkt.sp = 80;
        let a2 = call_head(&pkt, &rt2, &chain, 0, 1); // sp 80 in po -> fail
        pkt.sp = 8080;
        let a3 = call_head(&pkt, &rt2, &chain, 0, 0); // check_ports=0 -> pass
        r.p(&format!(
            "ARM noteq sp8080={} sp80={} cp0={}",
            a1, a2, a3
        ));
        let gchain = vec![
            snort3::detection::treenodes::RuleFpList {
                rule_head_func: snort3::detection::treenodes::RuleFuncId::Proto,
            },
            snort3::detection::treenodes::RuleFpList {
                rule_head_func: snort3::detection::treenodes::RuleFuncId::ListEnd,
            },
        ];
        pkt.proto_bits = pb_tcp;
        rt2.snort_protocol_id = 3; // tcp
        let b1 = call_head(&pkt, &rt2, &gchain, 0, 1);
        rt2.snort_protocol_id = 1;
        pkt.proto_bits = pb_udp; // ip legacy mask
        let b2 = call_head(&pkt, &rt2, &gchain, 0, 1);
        rt2.snort_protocol_id = 4;
        pkt.proto_bits = snort3::detection::rtn_checks::PROTO_BIT__PDU; // udp rule, pdu pkt
        let b3 = call_head(&pkt, &rt2, &gchain, 0, 1);
        rt2.snort_protocol_id = 5;
        pkt.proto_bits = snort3::detection::rtn_checks::PROTO_BIT__FILE; // file
        let b4 = call_head(&pkt, &rt2, &gchain, 0, 1);
        rt2.snort_protocol_id = 3;
        pkt.proto_bits = snort3::detection::rtn_checks::PROTO_BIT__PDU; // tcp rule, pdu pkt
        let b5 = call_head(&pkt, &rt2, &gchain, 0, 1);
        let b6 = call_head(&pkt, &rt2, &gchain, 0, 0); // check_ports=0 ignores proto
        r.p(&format!(
            "ARM proto tcp={} ip-udp={} udp-pdu={} file={} tcp-pdu={} cp0={}",
            b1, b2, b3, b4, b5, b6
        ));
    }

    // otn_map teardown (probe: delete sc->otn_map) then DONE
    r.sc.otn_map = OtnMap::default();
    r.p("DONE");

    // ---- compare in-process stream ------------------------------------------
    let vectors = include_str!("../tools/rules_harness/vectors.txt");
    let expected: Vec<&str> = vectors
        .lines()
        .take_while(|l| *l != "FATAL1 start")
        .map(|l| l.trim_end())
        .collect();
    let got: Vec<&str> = r.out.iter().map(|l| l.as_str()).collect();
    compare(&got, &expected);

    // ---- FATAL_DEMO subprocess channels -------------------------------------
    let fatal: Vec<&str> = vectors
        .lines()
        .skip_while(|l| *l != "FATAL1 start")
        .map(|l| l.trim_end())
        .collect();
    // probe-produced lines only (start/rc/end wrapper lines are build.sh's)
    let f1_at = fatal
        .iter()
        .position(|l| *l == "FATAL: ***PortVar Lookup failed on '$NOPE'.")
        .unwrap();
    let f2_at = fatal
        .iter()
        .position(|l| *l == "FATAL: ***Rule--PortVar Parse error: (pos=1,error=not a number)")
        .unwrap();
    let f3_at = fatal.iter().position(|l| *l == "FATAL3 start").unwrap() + 2;
    for (mode, at) in [(1usize, f1_at), (2, f2_at), (3, f3_at)] {
        let got = fatal_replay(mode);
        compare(&got.iter().map(|x| x.as_str()).collect::<Vec<&str>>(), &fatal[at..at + 2]);
    }
}

// Drive the FATAL_DEMO path through the real Rust port: ParseAbort must
// produce the FATAL diagnostics + "Fatal Error, Quitting.." exactly as the
// main-thread FatalError path does in C (the probe ran this as a
// subprocess because C terminates; the Rust port models the message
// sequence, and the process-exit itself is pinned by rc).
fn fatal_replay(mode: usize) -> Vec<String> {
    let mut r = Rep::setup_fatal();
    let mut rta = RuleTreeNode::new();
    if mode != 3 {
        parse_rule_type(&mut r.sc, Some("alert"), &mut rta);
        parse_rule_proto(&mut r.sc, "tcp", &mut rta, false);
        parse_rule_nets(&mut r.sc, "any", true, &mut rta, false);
    }
    let res = if mode == 3 {
        // ParseAbort fed through the real stream FSM.
        r.stream_rules_owned("alert tcp any $NOPE -> any any (sid:9; rev:1;)\n")
            .err()
    } else {
        let port = if mode == 1 { "$NOPE" } else { "notaport" };
        parse_rule_ports(&mut r.sc, port, true, &mut rta, false).err()
    };
    if res.is_none() {
        panic!("FATAL{mode}: expected the fatal port abort, got Ok");
    }
    // C exits(1) from FatalError; the Rust port models the process exit
    // with Fatal::Quitting — the pinned rc=1 corresponds to this value.
    assert_eq!(res.unwrap(), Fatal::Quitting);
    // drain then apply the build.sh emit_fatal filter verbatim:
    // `grep -e FATAL -e Quitting` (the \n>>notaport\n>>^ continuation
    // lines of the raw-literal abort never reach the locked transcript).
    r.drain();
    r.out
        .iter()
        .filter(|l| l.contains("FATAL") || l.contains("Quitting"))
        .cloned()
        .collect()
}

fn compare(got: &[&str], expected: &[&str]) {
    let mut first_diff: Option<(usize, String, String)> = None;
    for i in 0..std::cmp::max(got.len(), expected.len()) {
        let g = got.get(i).copied().unwrap_or("<eof>");
        let e = expected.get(i).copied().unwrap_or("<eof>");
        if g != e {
            first_diff = Some((i, g.to_string(), e.to_string()));
            break;
        }
    }
    if let Some((i, g, e)) = first_diff {
        let ctx_got: Vec<&str> =
            got[i.saturating_sub(6)..std::cmp::min(got.len(), i + 8)].to_vec();
        let ctx_exp: Vec<&str> =
            expected[i.saturating_sub(2)..std::cmp::min(expected.len(), i + 3)].to_vec();
        panic!(
            "rules transcript mismatch at line {}:\n  got context:      {ctx_got:?}\n  expected context: {ctx_exp:?}\n(got {} lines, expected {} lines)",
            i + 1,
            got.len(),
            expected.len()
        );
    }
    assert_eq!(got.len(), expected.len(), "transcript length mismatch");
}

// ---- rtn_checks replay helpers (probe rc_call / rc_first_rtn / RCFN) ----
fn mk_packet(
    pb: u32,
    sip_s: &str,
    dip_s: &str,
    sp: u16,
    dp: u16,
) -> snort3::detection::rtn_checks::PacketLite {
    // probe mk_packet: calloc mock + REAL IpApi::set(SfIp,SfIp) + REAL
    // SfIp::set(const char*) (SfIp::set_str in Rust).
    let mut ip_api = snort3::detection::rtn_checks::IpApiLite::default();
    let mut sip = snort3::sfip::sf_ip::SfIp::new();
    let mut dip = snort3::sfip::sf_ip::SfIp::new();
    sip.set_str(sip_s);
    dip.set_str(dip_s);
    ip_api.set(sip, dip);
    snort3::detection::rtn_checks::PacketLite {
        proto_bits: pb,
        sp,
        dp,
        ip_api,
    }
}

fn rc_fn_name(f: snort3::detection::treenodes::RuleFuncId) -> &'static str {
    use snort3::detection::treenodes::RuleFuncId as F;
    match f {
        F::ListEnd => "End",
        F::Bidirectional => "Bidi",
        F::Proto => "Proto",
        F::SrcIp => "SrcIP",
        F::DstIp => "DstIP",
        F::SrcPortEqual => "SpEq",
        F::DstPortEqual => "DpEq",
        F::SrcPortNotEq => "SpNe",
        F::DstPortNotEq => "DpNe",
    }
}

fn rc_first_rtn(otn: &Option<OtnHandle>) -> Option<RtnHandle> {
    let o = otn.as_ref()?;
    o.borrow().proto_nodes.iter().flatten().next().cloned()
}

#[allow(clippy::too_many_arguments)] // mirrors probe.cc rc_call arg-for-arg
fn rc_call(
    r: &mut Rep,
    tag: &str,
    otn: &Option<OtnHandle>,
    pb: u32,
    sip_s: &str,
    dip_s: &str,
    sp: u16,
    dp: u16,
) {
    let rtn = match rc_first_rtn(otn) {
        Some(h) => h,
        None => {
            r.p(&format!("{tag} NIL"));
            return;
        }
    };
    let rb = rtn.borrow();
    let pname = r.sc.proto_ref.get_name(rb.snort_protocol_id).to_string();
    let arms: Vec<&str> = rb.rule_func.iter().map(|f| rc_fn_name(f.rule_head_func)).collect();
    r.p(&format!("{} {} arms: {}", tag, pname, arms.join(" ")));
    let pkt = mk_packet(pb, sip_s, dip_s, sp, dp);
    let e1 = snort3::detection::rtn_checks::eval_rule(&pkt, &rb, 1);
    let e0 = snort3::detection::rtn_checks::eval_rule(&pkt, &rb, 0);
    r.p(&format!(
        "{} eval pb={:03X} sp={} dp={} cp1={} cp0={}",
        tag, pkt.proto_bits, pkt.sp, pkt.dp, e1, e0
    ));
}

fn rc_fn_scan(r: &mut Rep, sid: u32, otn: &Option<OtnHandle>) {
    let mut s = format!("RCFN {}", sid);
    if let Some(o) = otn {
        let ob = o.borrow();
        for (i, n) in ob.proto_nodes.iter().enumerate() {
            if let Some(h) = n {
                s.push_str(&format!(" n{}={:02X}", i, h.borrow().flags));
            }
        }
    }
    r.p(&s);
}
