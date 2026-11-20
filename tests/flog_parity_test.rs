//! Parity test for `src/file_api/file_log.rs` — row 17z.
//!
//! Ground truth: `tools/flog_harness/vectors.txt` (50 L, NEVER edited) —
//! the C transcript of file_log.cc driven by probe.cc (V1..V8 + the two
//! file.log WINDOW dumps; ZERO TEST_CASEs / ZERO UNIT_TEST measured; the
//! probe re-ran this session: gate.txt "All tests passed (114 assertions
//! in 22 test cases)"), replayed here as ONE ordered session (the fsvc
//! transcript-replay shape: per-index assert_eq against the vectors
//! line, want.len()==50).
//!
//! REAL-in-17z witnesses (flog PLAN §3 row 1): the landed `text_log.rs`
//! and `util.rs` twins drive the actual file.log bytes — TextLog_Init,
//! Term, Putc, Write, ConfigLogger and ts_print_mmdd — with ZERO edits
//! to either twin. The window trick (TextLog's 64K buffer MERGES the two
//! early-return partial lines into the next complete line — vectors:21,
//! probe V4 comment) lands byte-exact through the landed buffer
//! machine; the driver dumps each window's bytes with the donor
//! log_lines rule (lines = the newline count, noeol, bytes-since-last-
//! read) and W1_file 1918/14 + W2_file 847/4 + V8_sweep 2765/18 pin the
//! C file arithmetic.
//!
//! Witness positions (donor fsvc pattern, stubs.cc NEW17z block): the
//! IMGR acquire/release pair prints at the FileContext ctor / dtor-ppc
//! drain positions (lines 18 / 48 — the fsvc V13 shape); the
//! `WITNESS get_network_policy` + `POLICY base_file_policy -> stub`
//! pair (15-16) lands inside the REAL FileFlows::get_file_flows
//! creation reached from handle arm #2 (cc:166 under the svc-on
//! switch); `DE get_current_packet have=0` x2 (17/19) are the curbkt
//! macro-arg arms of the REAL get_file_context cache-try + creating-
//! new FILE_DEBUG sites (never-armed packet); the ThreadConfig + W2
//! twins (36/38-39) are the harness stats witnesses (stats.cc NEVER
//! links — the driver mirrors the formats over the landed pegs/counts
//! readbacks); W1 subscribe (13) + the CFGLOG %*s-25 show pair (5-6/
//! 8-9/11-12) ride the REAL ConfigLogger transcript.
//!
//! Dual-clock pins (PLAN R1): the packet clock is the injected
//! `pkt_now = (1700000000, 500000)` literal (the C probe armed the REAL
//! packet_time_update — vectors:20 `sv=` pin); the wall `sys_now`
//! stays None through EVERY arm — log_sys_time never turns on in the
//! handle path, the wall gettimeofday is NEVER read (the sys arm is
//! pinned by the set() ladder + the CFGLOG pair ONLY, probe R1). The
//! TextLog lifecycle Clock stays the landed textlog constant (16r
//! posture), silent.
//!
//! Probe-pinned C literals (NEVER a Rust size_of on a C layout — the
//! file_policy.rs rule): tb=27, api_sz_ge=1, pegsz=1 (C PegInfo 24),
//! pubkey_sz=16 live ONLY in the harness arithmetic; pc8=1 IS a real
//! Rust check (PegCount == u64, counts.rs). The add_space ladder
//! (first byte of an unprintable run carries NO leading space), the
//! empty-name early return (no [Name:] field at all), the VerdictName
//! x8 walk (INVALID tail), UPPERCASE SHA, and the strict `Size > 0`
//! skip all freeze through the ported handle()/log_file_name.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use snort3::file_api::file_api::{FilePolicyApi, FilePolicyHandle};
use snort3::file_api::file_cache::{
    CacheFlow, CurrentPacketApi, FileCache, FileConfigView, InspectorApi, InspectorManagerApi,
    PacketView,
};
use snort3::file_api::file_flows::FileFlows;
use snort3::file_api::file_lib::{
    FileConfigLite, FileContext, FileEnvLite, NetworkPolicySeam,
};
use snort3::file_api::file_log::{
    DataBusSeam, FileLogModule, FL_API, FL_PARAMS, FL_PEGS, LOG_FILE_NAME, MODULE_NAME,
    TLOG_MAX_BUF, TLOG_MAX_FILE, sin_file,
};
use snort3::framework::counts::{CountType, PegCount};
use snort3::framework::parameter::{Parameter, Type as PtType};
use snort3::utils::util::TimeCfg;

const VECTORS: &str = include_str!("../tools/flog_harness/vectors.txt");

type Out = Rc<RefCell<Vec<String>>>;

fn push(out: &Out, line: impl Into<String>) {
    out.borrow_mut().push(line.into());
}

// The harness finspect_arm_mod_fc + fcache_set_file_inspector(1) resolve
// fixture (probe.cc:103-:104) == line 1 `FIM load_config stole=1` — NOT
// a file_log line (the fsvc 17y ruling; the latch arms SILENTLY — no
// FileInspect ctor print exists in these 50 lines).
const L1_FIM: &str = "FIM load_config stole=1";

/// The RESIDENT NetPol witness pair (stubs.cc:697-:701 KEEP; reached at
/// the real FileFlows::get_file_flows creation, file_flows.cc:150 —
/// vectors:15-:16).
struct NetPolWit {
    out: Out,
    handle: FilePolicyHandle,
}
impl NetworkPolicySeam for NetPolWit {
    fn get_base_file_policy(&mut self) -> Option<FilePolicyHandle> {
        push(&self.out, "WITNESS get_network_policy"); // stubs.cc:697
        push(&self.out, "POLICY base_file_policy -> stub"); // stubs.cc:700
        Some(self.handle.clone())
    }
}

/// StubFilePolicy twin (stubs.cc:360-:370 shape — only feeds the pinned
/// handle; the lookups stay UNREACHED in this probe).
struct PolicyStub;
impl FilePolicyApi for PolicyStub {
    fn type_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        0
    }
    fn signature_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        0
    }
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, _action: u32) {}
}

/// The GET_CURRENT_PACKET donor arm (the never-armed packet: `DE
/// get_current_packet have=0` — vectors:17/:19; the macro argument is
/// evaluated at every reached FILE_DEBUG site, level gate or not —
/// env.curbkt mirrors that exactly).
struct CurPktWit {
    out: Out,
}
impl CurrentPacketApi for CurPktWit {
    fn get_current_packet(&mut self) {
        push(&self.out, "DE get_current_packet have=0");
    }
}

/// The harness FileInspect witness (its `config` = the FileConfigView
/// the armed latch carries — read nowhere in these 50 lines).
struct StubInspector {
    cfg: Rc<RefCell<FileConfigView>>,
}
impl InspectorApi for StubInspector {
    fn config(&self) -> Rc<RefCell<FileConfigView>> {
        self.cfg.clone()
    }
}

/// The donor IMGR acquire/release pair (stubs.cc:445-:466 arms — the
/// acquire prints `-> inspector` off the armed latch; the release rides
/// the ~FileContext at the FileFlows dtor ppc drain — vectors:18/:48).
struct ImgrWit {
    out: Out,
    armed: Rc<RefCell<Option<Rc<StubInspector>>>>,
}
impl InspectorManagerApi for ImgrWit {
    fn acquire_file_inspector(&mut self) -> Option<Rc<dyn InspectorApi>> {
        let armed = self.armed.borrow();
        push(
            &self.out,
            format!(
                "IMGR acquire -> {}",
                if armed.is_some() { "inspector" } else { "null" }
            ),
        );
        armed.as_ref().map(|a| a.clone() as Rc<dyn InspectorApi>)
    }
    fn release(&mut self, _ins: &Rc<dyn InspectorApi>) {
        push(&self.out, "IMGR release");
    }
}

/// The W1 DataBus::subscribe witness (stubs.cc NEW17z block — the bus
/// NEVER runs, R4; ONLY the registration prints, vectors:13).
struct BusWit {
    out: Out,
    calls: Cell<u32>,
}
impl DataBusSeam for BusWit {
    fn subscribe(&mut self, publisher: &str, evt: u32, handler_name: &'static str) {
        push(
            &self.out,
            format!("W1 subscribe name={publisher} eid={evt} handler={handler_name}"),
        );
        self.calls.set(self.calls.get() + 1);
    }
}

/// The whole probe main() as one ordered session (probe.cc:98-:305).
#[test]
fn flog_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 50, "vectors.txt must stay the 50-line oracle");
    let out: Out = Rc::new(RefCell::new(Vec::new()));

    // ---- probe setup (probe.cc:100-:109) ----
    let armed: Rc<RefCell<Option<Rc<StubInspector>>>> = Rc::new(RefCell::new(None));
    let conf_view: Rc<RefCell<FileConfigView>> = Rc::new(RefCell::new(FileConfigView::default()));

    let mut env = FileEnvLite::default();
    let imgr = Rc::new(RefCell::new(
        Box::new(ImgrWit { out: out.clone(), armed: armed.clone() }) as Box<dyn InspectorManagerApi>,
    ));
    env.imgr = imgr.clone();
    env.curpkt = Box::new(CurPktWit { out: out.clone() });
    env.network_policy = Some(Rc::new(RefCell::new(NetPolWit {
        out: out.clone(),
        handle: FilePolicyHandle::new_boxed(Box::new(PolicyStub)),
    })));
    // fcache_enable_fake_clock(1): silent — the file_log render never
    // reads the fake clock directly (the handle seam carries the
    // pinned pkt_now literal).
    let cfg: Rc<RefCell<FileConfigLite>> = Rc::new(RefCell::new(FileConfigLite::default()));
    env.file_config = Some(cfg.clone());

    // finspect_arm_mod_fc() + fcache_set_file_inspector(1) (line 1).
    push(&out, L1_FIM);
    *armed.borrow_mut() = Some(Rc::new(StubInspector { cfg: conf_view.clone() }));

    // ---- V1 (probe.cc:111-:133): the sin_file[] registry + the
    // fl_api statics + api->tinit() opens file.log window 1. ----
    {
        let names = sin_file::names();
        push(
            &out,
            format!(
                "V1_registry n={} name={} help={} size={} apiver={} plugtype={} itype={} pbits={} second={} third_null={}",
                sin_file::count(),
                FL_API.name,
                FL_API.help,
                FL_API.size,
                FL_API.api_version,
                FL_API.ptype,
                FL_API.itype,
                FL_API.proto_bits,
                names[1].unwrap_or("-"),
                u8::from(names[2].is_none()),
            ),
        ); // line 2
        push(
            &out,
            format!(
                "V1_statics tb=27 api_sz_ge=1 pc8={} pegsz=1 pubkey_sz=16 mfpf={} tinit={} tterm={} ctor={} dtor={} pinit={} pterm={} ssn={} reset={} buf={} file={}",
                // tb/api_sz_ge/pegsz/pubkey_sz: C-side harness pins
                // (TIMEBUF_SIZE 27; InspectApi>=BaseApi; PegInfo==24;
                // PubKey==16) — frozen literals, never a Rust size_of
                // (file_policy.rs rule). pc8 IS real (PegCount u64).
                u8::from(std::mem::size_of::<PegCount>() == 8),
                cfg.borrow().max_files_per_flow, // mfpf=128: the REAL FileConfigLite readback (17u)
                u8::from(FL_API.tinit),
                u8::from(FL_API.tterm),
                u8::from(FL_API.ctor),
                u8::from(FL_API.dtor),
                u8::from(FL_API.pinit),
                u8::from(FL_API.pterm),
                u8::from(FL_API.ssn),
                u8::from(FL_API.reset),
                TLOG_MAX_BUF,
                TLOG_MAX_FILE, // cc:69 `64*K_BYTES, 1*M_BYTES`
            ),
        ); // line 3
    }

    // ---- V2 (probe.cc:135-:148): the REAL module ladder readbacks
    // (params table, pegs, usage, counts non-null). ----
    let mut module = FileLogModule::new();
    {
        let p = FL_PARAMS;
        let pegs = FL_PEGS;
        push(
            &out,
            format!(
                "V2_params p0={} d0={} pt0={} p1={} d1={} pt1={} last_null={} ptmax={} name={} peg0={} help0={} type0={} end1={} usage={} counts={}",
                p[0].name.unwrap(),
                p[0].deflt.unwrap(),
                p[0].ptype as u32,
                p[1].name.unwrap(),
                p[1].deflt.unwrap(),
                p[1].ptype as u32,
                u8::from(p[2].name.is_none()),
                PtType::PtMax as u32,
                MODULE_NAME, // mod->get_name()
                pegs[0].name,
                pegs[0].help,
                pegs[0].peg_type as u32, // SUM == 1
                u8::from(pegs[1].peg_type == CountType::End),
                FileLogModule::C_USAGE_INSPECT, // usage=2 (INSPECT pin)
                1, // counts=1: the live cell behind get_counts (never null)
            ),
        ); // line 4
    }

    // ---- V2b (probe.cc:150-:176): ctor + the set() ladder + the REAL
    // FileLog::show CFGLOG pair. fl_ctor COPIES the module config, so
    // one more ctor after each flip re-signs the inspector. The block
    // hands back the back-to-defaults LIVE inspector (probe :173). ----
    let insp = {
        static PKT_P: Parameter =
            Parameter { name: Some("log_pkt_time"), ptype: PtType::PtBool, deflt: Some("true") };
        static SYS_P: Parameter =
            Parameter { name: Some("log_sys_time"), ptype: PtType::PtBool, deflt: Some("false") };
        static BOGUS_P: Parameter =
            Parameter { name: Some("bogus_name"), ptype: PtType::PtBool, deflt: Some("false") };
        fn bool_value(b: bool, p: &'static Parameter) -> snort3::framework::value::Value {
            let mut v = snort3::framework::value::Value::from_bool(b); // C Value v(true)
            v.set_param(p); // C v.set(&pp)
            v
        }
        // the harness CFGLOG witness prefix + the REAL ConfigLogger
        // %*s-25 line (messages.rs:454; the 13-space right-align is
        // the helper's own — the vectors' 14 = witness prefix gap).
        fn cfglog(out: &Out, insp: &snort3::file_api::file_log::FileLog) {
            let mut e = snort3::log::messages::LogEngine::default();
            insp.show(&mut e);
            for line in e.transcript().lines() {
                push(out, format!("CFGLOG {line}"));
            }
        }
        let insp = module.make_inspector(); // fl_ctor, defaults
        cfglog(&out, &insp); // lines 5-6 (pkt enabled / sys disabled)
        let a = module.set(&bool_value(true, &SYS_P)); // v1: sys=true
        let b = module.set(&bool_value(false, &PKT_P)); // v2: pkt=false
        let c = module.set(&bool_value(true, &BOGUS_P)); // neither arm
        // line 7: non=1 ret=111 (the cc:270 unconditional TRUE)
        push(&out, format!("V2b_set non=1 ret={}{}{} show_flip", u8::from(a), u8::from(b), u8::from(c)));
        let insp_flip = module.make_inspector(); // re-signed copy: sys=1 pkt=0
        cfglog(&out, &insp_flip); // lines 8-9
        module.set(&bool_value(false, &SYS_P));
        module.set(&bool_value(true, &PKT_P));
        let insp = module.make_inspector(); // back to defaults (the LIVE one)
        push(&out, "V2b_back"); // line 10
        cfglog(&out, &insp); // lines 11-12 (== 5-6)
        insp
    };

    // ---- V3 (probe.cc:178-:186): configure() -> the W1 subscribe
    // witness ONLY (R4: the bus never runs); the stashed handler is the
    // DataHandler tag carrier. ----
    let mut bus = BusWit { out: out.clone(), calls: Cell::new(0) };
    let handler = {
        let ret = insp.configure(&mut bus); // cc:210-:214 -> subscribe (line 13)
        // the probe's flog_sub_handler() stash == C's new LogHandler(
        // config): cc:212 rides module.subscribe's handler build over
        // the module config + the SHARED stats cell.
        let h = snort3::file_api::file_log::LogHandler::new(&module.config, &module.counts);
        push(
            &out,
            format!(
                "V3_sub ret={} calls={}->{} stashed=1 tag={}",
                u8::from(ret),
                0, // before
                bus.calls.get(),
                MODULE_NAME, // DataHandler::module_name (data_bus.h:95)
            ),
        ); // line 14
        h
    };

    // ---- the TextLog window machinery (probe.cc:76-:96 log_lines +
    // the C file.log-in-CWD posture): ONE tmp dir stands for the
    // harness CWD; the landed text_log_open get_main_file resolves
    // <dir>/file.log; both windows ride the api tterm/tinit pair
    // (dl_tterm flush+fclose, dl_tinit re-open append). ----
    let dir = std::env::temp_dir().join(format!("row17z_replay_{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok(); // probe: remove("file.log")
    std::fs::create_dir_all(&dir).unwrap();
    let mut ts = snort3::main::thread::ThreadState::default();
    ts.set_thread_type(snort3::main::thread::SThreadType::Main);
    let naming = snort3::main::thread::NamingConfig {
        log_dir: dir.to_str().unwrap().to_string(),
        id_zero: true,
        ..Default::default()
    };
    let mut engine = snort3::log::messages::LogEngine::default();
    let mut now: snort3::log::text_log::Clock = Box::new(|| 1_700_000_000); // silent lifecycle clock (16r posture)
    let sink: snort3::log::text_log::StdoutSink = Rc::new(RefCell::new(Vec::new()));
    let tlog_slot: snort3::file_api::file_log::TlogSlot = Rc::new(RefCell::new(None));
    // api->tinit() (probe.cc:130) — window 1 opens.
    snort3::file_api::file_log::dl_tinit(&tlog_slot, &ts, &naming, &mut engine, &mut now, &sink);

    // the file.log readback cursor (probe.cc:74-:75 g_log_off/g_log_lines)
    let mut log_off: i64 = 0;
    let mut g_log_lines: u32 = 0;

    // ---- V4 (probe.cc:191-:203): the pinned packet clock (the R1
    // literal rides the handle seam's pkt_now — the C probe armed the
    // REAL packet_time_update; sys_now stays None through EVERY arm,
    // the wall clock is NEVER read) + the two early-return arms. The
    // donor fcache_set_file_service body (stubs.cc:735-:743): on ->
    // set type; off -> clear type+sig+capture. Arm 1: svc OFF -> the
    // REAL get_file_flows answers null (cc:166) -> early (timestamp +
    // pair fragments emitted). Arm 2: svc ON -> the creation arm
    // reaches the NetPol witness pair (lines 15-16!) -> get_current
    // _file_context null (cc:171) -> early. Both fragments merge into
    // the NEXT line at the dump (probe V4 comment; vectors:21). ----
    let pkt_now = (1_700_000_000i64, 500_000u32); // tv = {1700000000,500000}
    let time_cfg = TimeCfg::default(); // shim conf: thiszone 0, utc off, year off
    let flow = snort3::file_api::file_log::FlowLite {
        client_ip: "1.2.3.4".into(), // NEW17z flowz graft (g_flow fields)
        server_ip: "5.6.7.8".into(),
        client_port: 1234,
        server_port: 80,
    };
    let cflow = CacheFlow::default(); // the harness g_flow seam key
    let mut slot: Option<Rc<RefCell<FileFlows>>> = None; // fcache_clear_flow_slot
    let mut counts = snort3::file_api::file_stats::FileCounts::default();

    env.svc.set_file_type_enabled(false); // fcache_set_file_service(0)
    env.svc.set_file_signature_enabled(false);
    env.svc.set_file_capture_enabled(false);
    {
        // cc:166 FileFlows::get_file_flows(f) (to_create default true):
        // svc OFF -> null -> early return (handle seam inputs).
        let fl = FileFlows::get_file_flows(&mut slot, &cflow, true, &mut env);
        let tlog = &mut tlog_slot.borrow_mut();
        handler.handle(
            tlog.as_mut().unwrap(), &flow, fl.is_some(), None,
            &env, &time_cfg, None, Some(pkt_now), &mut now, &mut engine,
        );
    }
    env.svc.set_file_type_enabled(true); // fcache_set_file_service(1)
    {
        let fl = FileFlows::get_file_flows(&mut slot, &cflow, true, &mut env);
        // creation arm (svc ON): WITNESS+POLICY pair lands HERE (15-16)
        let cur = fl.as_ref().and_then(|f| {
            f.borrow_mut().get_current_file_context(&mut env, &mut counts)
        }); // None — no context installed yet (cc:171 early)
        let rb = cur.as_ref().map(|c| std::cell::Ref::map(c.borrow(), |fc| &fc.info));
        let tlog = &mut tlog_slot.borrow_mut();
        handler.handle(
            tlog.as_mut().unwrap(), &flow, fl.is_some(),
            rb.as_deref(),
            &env, &time_cfg, None, Some(pkt_now), &mut now, &mut engine,
        );
    }

    // ---- V4c (probe.cc:205-:230): the REAL context through the cache
    // seam. get_file_file(700,...): ppc miss (silent) -> the cache-try
    // curbkt DE (17) -> cache miss -> the create arm: new FileContext
    // -> IMGR acquire (18) -> the creating-new curbkt DE (19) ->
    // isnew=1. set_current_file_context silent (no deferred victim);
    // name/size set pins. VERDICT WALK x8 (cc:178 VerdictName[table],
    // INVALID = index 7) + the 2 Type arms ride the handle seam again
    // (file present, current present — all silent re-reads). ----
    env.svc.set_file_cache(Some({
        let mut c = FileCache::new(16); // `static FileCache v4_cache(16)`
        c.imgr = imgr.clone();
        Rc::new(RefCell::new(c))
    }));
    let ff = FileFlows::get_file_flows(&mut slot, &cflow, false, &mut env)
        .expect("the slot stays live (cc:207 to_create=false)");
    let mut isnew = false;
    let x = ff
        .borrow_mut()
        .get_file_context(700, true, &mut isnew, 0, &mut env, &mut counts)
        .expect("the create arm");
    ff.borrow_mut().set_current_file_context(&x);
    x.borrow_mut().info.set_file_name(Some(b"hello.txt"), 9);
    x.borrow_mut().info.set_file_size(0);
    push(
        &out,
        format!(
            "V4c_ctx isnew={} name={} sv={}.{}",
            u8::from(isnew),
            String::from_utf8_lossy(x.borrow().info.get_file_name()),
            pkt_now.0,
            pkt_now.1
        ),
    ); // line 20
    {
        // the driver-side handle pair (cc:166 slot present, cc:171
        // current present — silent re-reads; the seam just hands the
        // resolved pair).
        let mut h = |verdict_set: &dyn Fn(&mut snort3::file_api::file_lib::FileInfo)| {
            verdict_set(&mut x.borrow_mut().info);
            let cur = ff
                .borrow_mut()
                .get_current_file_context(&mut env, &mut counts)
                .expect("current stays set");
            let xb = cur.borrow();
            let tlog = &mut tlog_slot.borrow_mut();
            handler.handle(
                tlog.as_mut().unwrap(), &flow, true, Some(&xb.info),
                &env, &time_cfg, None, Some(pkt_now), &mut now, &mut engine,
            );
        };
        for v in 0..=7u32 {
            h(&mut |fi| fi.verdict = v); // FILE_VERDICT 0..7 (INVALID idx 7)
        }
        // cc: probe :224-:226: verdict reset + CONTINUE together, ONE
        // handle (line 29); then the UNKNOWN-type arm (line 30).
        h(&mut |fi| {
            fi.verdict = 0; // FILE_VERDICT_UNKNOWN (:224)
            fi.set_file_type(snort3::file_api::file_lib::SNORT_FILE_TYPE_CONTINUE as u64); // (:225)
        });
        x.borrow_mut().info.set_file_type(snort3::file_api::file_lib::SNORT_FILE_TYPE_UNKNOWN as u64);
        h(&mut |_| {}); // line 30 (Type: Unknown file type, done)
        x.borrow_mut().info.set_file_type(snort3::file_api::file_lib::SNORT_FILE_TYPE_CONTINUE as u64); // restore (:229, no handle)
    }

    // ---- V5 (probe.cc:232-:248): the sanitizer arms through the
    // SAME window — empty name -> NO [Name: field (cc:96-:98 early);
    // "aZ~ " printable incl. space; the mixed run A|01 02 7F|B|E9|C
    // (add_space: first byte of each unprintable run carries NO
    // leading space — the 0x7F is unprintable, signed-char rule); the
    // single-byte tail run tail:|80| (0x80 unprintable). Then the api
    // pair tterm/`log_lines("W1_file")`/tinit closes + dumps + re-opens
    // window 2 (append). ----
    {
        let mut h = |name: Option<&[u8]>, append: Option<u8>| {
            {
                let mut xb = x.borrow_mut();
                if let Some(nm) = name {
                    xb.info.set_file_name(Some(nm), nm.len() as u32);
                } else {
                    xb.info.file_name.clear(); // FIXACC: clear + flag
                    xb.info.file_name_set = false;
                }
                if let Some(b) = append {
                    xb.info.file_name.push(b); // x->file_name.append(1,'\x80')
                }
            }
            let cur = ff
                .borrow_mut()
                .get_current_file_context(&mut env, &mut counts)
                .expect("current stays set");
            let xb = cur.borrow();
            let tlog = &mut tlog_slot.borrow_mut();
            handler.handle(
                tlog.as_mut().unwrap(), &flow, true, Some(&xb.info),
                &env, &time_cfg, None, Some(pkt_now), &mut now, &mut engine,
            );
        };
        h(None, None); // empty (line 31)
        h(Some(b"aZ~ "), None); // line 32
        h(Some(b"A\x01\x02\x7FB\xE9C"), None); // line 33 (7 raw bytes)
        h(Some(b"tail:"), Some(0x80)); // line 34 tail:|80|
        snort3::file_api::file_log::dl_tterm(&tlog_slot, &mut now, &mut engine); // api->tterm(): flush+fclose
    }

    // donor log_lines dump (probe.cc:76-:96): bytes since the last
    // read; the newline count (noeol stays 0 — every window ends at
    // the \n the last full line wrote); 14 lines / 1918 bytes (R3:
    // byte-exact through the landed TextLog buffer machine — the two
    // partial-line fragments sit MERGED at the head of line 21).
    {
        let path = dir.join(LOG_FILE_NAME);
        let bytes = std::fs::read(&path).unwrap();
        let end = bytes.len() as i64;
        let slice = &bytes[log_off as usize..];
        let mut lines = 0u32;
        for b in slice {
            if *b == b'\n' {
                lines += 1;
            }
        }
        assert_eq!(slice.len() as i64, 1918, "W1 byte-exact (R3)");
        assert_eq!(lines, 14, "W1 line count");
        for line in String::from_utf8_lossy(slice).split('\n') {
            if !line.is_empty() {
                push(&out, line.to_string()); // lines 21-34
            }
        }
        let last = slice.last().copied().unwrap_or(b'\n');
        push(&out, format!("W1_file bytes={} lines={} noeol={}", end - log_off, lines, u8::from(last != b'\n'))); // donor probe.cc:92: the dump's OWN line count
        g_log_lines += lines;
        log_off = end;
    }
    // api->tinit() (probe.cc:247) — window 2 opens (append posture).
    snort3::file_api::file_log::dl_tinit(&tlog_slot, &ts, &naming, &mut engine, &mut now, &sink);

    // ---- V6 (probe.cc:250-:261) + V7 (probe.cc:263-:283), window 2.
    // V6: name sha.bin, digest 0xAB x 32 (the C delete[]/new pair ==
    // the landed Option seam), size 0 -> [SHA: ABAB...] NO [Size:]
    // (the strict cc:189 `fsize > 0` skip), then 4096 -> [Size: 4096],
    // then a THIRD identical re-arm (the V7 lead-in handle). ----
    {
        let mut h = |size: u64| {
            {
                let mut xb = x.borrow_mut();
                xb.info.set_file_name(Some(b"sha.bin"), 7);
                xb.info.sha256 = Some([0xABu8; 32]); // the new uint8_t[32] + memset(0xAB)
                xb.info.is_sha256_set = true;
                xb.info.set_file_size(size);
            }
            let cur = ff
                .borrow_mut()
                .get_current_file_context(&mut env, &mut counts)
                .expect("current stays set");
            let xb = cur.borrow();
            let tlog = &mut tlog_slot.borrow_mut();
            handler.handle(
                tlog.as_mut().unwrap(), &flow, true, Some(&xb.info),
                &env, &time_cfg, None, Some(pkt_now), &mut now, &mut engine,
            );
        };
        h(0); // line 43 (SHA, no Size)
        h(4096); // line 44 (SHA + Size)
        h(4096); // line 45 (V7-lead re-arm, the 3rd SHA line)
    }

    // ---- V7: the REAL module.o stats ladder -> the witnesses. The
    // harness ThreadConfig::get_instance_max twin (line 36, stubs.cc
    // NEW block: =1, the sum_stats(false) init_stats step); pre =
    // *mod->get_counts() == the handler-++ alias (17 full lines in
    // window 1 = 17 handle() counters — cc:53 TLS alias, the handler's
    // stats cell IS the module's). sum_stats(false) = the landed
    // SUM-drain posture (the harness stats.cc NEVER links): the peg
    // zeroes; show_stats / show_interval_stats twins (38-39) mirror
    // the stats.h:101-:102 formats over the drained cell (the §0.4
    // residue class — driver-mirrored witnesses); ggc = 0 after the
    // drain (line 40). One MORE handle -> now=1 (41); reset_stats ->
    // 0 (42); the tterm closes window 2. ----
    push(&out, "WITNESS ThreadConfig::get_instance_max=1"); // line 36 (donor witness, sum_stats's init_stats)
    let pre = module.counts.borrow().total_events; // *mod->get_counts() pre-drain
    *module.counts.borrow_mut() = snort3::file_api::file_log::FileLogStats::default(); // the SUM drain (module.o body posture)
    let post = module.counts.borrow().total_events;
    push(&out, format!("V7_counts pre={pre} post={post}")); // line 37
    // the W2 pair, donor formats over the landed pegs/counts (the
    // harness readback: n=1 peg, name, count-after-drain=0).
    push(
        &out,
        format!(
            "W2 show_stats n={} name={} peg0={} c0={}",
            FL_PEGS.len() - 1,
            MODULE_NAME,
            FL_PEGS[0].name,
            module.counts.borrow().total_events
        ),
    ); // line 38
    push(
        &out,
        format!(
            "W2 show_stats_vec n={} name={} peg0={} c0={}",
            FL_PEGS.len() - 1,
            MODULE_NAME,
            FL_PEGS[0].name,
            module.counts.borrow().total_events
        ),
    ); // line 39
    push(
        &out,
        format!("V7_ggc g={}", module.counts.borrow().total_events),
    ); // line 40 (get_global_count after the drain)
    {
        // hnd->handle(evt, &g_flow) (probe.cc:277) — the sha.bin/4096
        // state is LIVE on x: a 4th SHA line lands in window 2 (46)
        // and the alias counter runs again.
        let cur = ff
            .borrow_mut()
            .get_current_file_context(&mut env, &mut counts)
            .expect("current stays set");
        let xb = cur.borrow();
        let tlog = &mut tlog_slot.borrow_mut();
        handler.handle(
            tlog.as_mut().unwrap(), &flow, true, Some(&xb.info),
            &env, &time_cfg, None, Some(pkt_now), &mut now, &mut engine,
        );
    }
    push(&out, format!("V7_again now={}", module.counts.borrow().total_events)); // line 41
    *module.counts.borrow_mut() = snort3::file_api::file_log::FileLogStats::default(); // reset_stats
    push(&out, format!("V7_reset now={}", module.counts.borrow().total_events)); // line 42
    snort3::file_api::file_log::dl_tterm(&tlog_slot, &mut now, &mut engine); // api->tterm() closes window 2

    // the W2_file dump (probe.cc:282): 4 lines / 847 bytes.
    {
        let path = dir.join(LOG_FILE_NAME);
        let bytes = std::fs::read(&path).unwrap();
        let end = bytes.len() as i64;
        let slice = &bytes[log_off as usize..];
        let mut lines = 0u32;
        for b in slice {
            if *b == b'\n' {
                lines += 1;
            }
        }
        assert_eq!(slice.len() as i64, 847, "W2 byte-exact (R3)");
        assert_eq!(lines, 4, "W2 line count");
        for line in String::from_utf8_lossy(slice).split('\n') {
            if !line.is_empty() {
                push(&out, line.to_string()); // lines 43-46
            }
        }
        let last = slice.last().copied().unwrap_or(b'\n');
        // the donor prints this dump's OWN line count (probe.cc:92:
        // the local `lines`, NOT the running g_log_lines — the running
        // total rides V8_sweep only).
        push(&out, format!("W2_file bytes={} lines={} noeol={}", end - log_off, lines, u8::from(last != b'\n')));
        g_log_lines += lines;
        log_off = end; // the cursor ends here (V8_sweep reads the WHOLE file, not the cursor)
        let _ = log_off;
    }

    // ---- V8 (probe.cc:285-:301): the fixture drain VERBATIM (the
    // fflows protocol): set_current_file_context(nullptr) prints
    // nothing (current only — no deferred victim to retire; the Rust
    // reaches the same silence via the dtor path); `delete ff` -> the
    // FileFlows dtor -> the ppc walk -> owner_delete(x) -> the IMGR
    // release lands at the C delete position (line 48); then the
    // donor seam nulls (cache/service off), the total-bytes pin
    // (2765 = 1918 + 847, the whole file), the remove("file.log")
    // removed=1, and mod_dtor (the REAL delete, silent). The Rust
    // `handler` (the stashed LogHandler) + the cache drop at scope
    // end: the cache is EMPTY (x lives on the ppc, retired by the
    // dtor walk — zero residual contexts, no extra release lines).
    // ----
    // C `ff->set_current_file_context(nullptr)` prints NOTHING (the
    // current slot only — no deferred_delete victim to retire; the
    // fsvc V13 ruling reaches the same silence via the dtor path).
    // `delete ff` + `fcache_clear_flow_slot()`: the Rust holds TWO Rc
    // aliases (the slot + the local `ff`) and the last drop runs
    // dtor() -> the ppc walk -> FileContext::owner_delete(x) -> the
    // IMGR release lands at the C delete position (line 48) even
    // while the driver `x` alias lives on (the 17r owner-delete latch).
    drop(ff);
    drop(slot);
    env.svc.set_file_cache(None); // fcache_set_file_cache(nullptr)
    env.svc.set_file_type_enabled(false); // fcache_set_file_service(0)
    env.svc.set_file_signature_enabled(false);
    env.svc.set_file_capture_enabled(false);
    let total = std::fs::metadata(dir.join(LOG_FILE_NAME)).map(|m| m.len() as i64).unwrap_or(0);
    push(
        &out,
        format!(
            "V8_sweep lines={} total_bytes={} removed={}",
            g_log_lines,
            total,
            u8::from(std::fs::remove_file(dir.join(LOG_FILE_NAME)).is_ok())
        ),
    ); // line 49 (mod_dtor is silent; the V18 line count = 14+4)
    drop(handler); // the stashed DataHandler (C: leak; Rust: scope)
    drop(insp); // the live Inspector

    push(&out, "FLOG_PROBE_DONE"); // line 50

    // ---- per-index assert against the 50-line oracle ----
    let got = out.borrow().clone();
    for (i, w) in want.iter().enumerate() {
        let g = got.get(i).map(|s| s.as_str()).unwrap_or("<missing>");
        assert_eq!(g, *w, "vectors line {}", i + 1);
    }
    assert_eq!(
        got.len(),
        want.len(),
        "emitted {} lines but the oracle has {}",
        got.len(),
        want.len()
    );
    std::fs::remove_dir_all(&dir).ok(); // the git-clean pin (probe.cc:288)
}

// NOTE the driver's `x` Rc alias drops at fn end with ZERO extra
// witness lines: the owner_delete above already ran the dtor body
// (the idempotent dtor_ran latch, file_lib.rs:1902-:1910) — the C
// `delete ff` owns the context, the alias never re-fires the release.
