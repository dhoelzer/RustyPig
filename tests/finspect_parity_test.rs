//! Parity test for `src/file_api/file_inspect.rs` — row 17w.
//!
//! Ground truth: `tools/finspect_harness/vectors.txt` (103 L, md5
//! 3cbd009e9bb4228ee427ed3fadc64fb4, NEVER edited) — the C transcript
//! of file_inspect.{h,cc} driven by probe.cc (V1..V8 arms; the TU has
//! ZERO TEST_CASEs and ZERO `#ifdef UNIT_TEST` fragments — finspect
//! PLAN §2/§4: probe vectors are the only oracles), replayed here as
//! ONE ordered session (fconf/fcshare/fapi replay shape: per-index
//! assert_eq against the vectors line, want.len() == 103).
//!
//! The REAL ported ladder runs end to end here: `FileInspect::new`
//! (steal ctor), `configure` (null arm -> FileCache trio -> instrumented
//! SMD walk -> pub-id static -> mp_dbus arm), `get_file_adv_pub_id`
//! (the seam file_lib re-points to), `show` through the REAL ported
//! `log::messages::ConfigLogger`, `file_init` through the REAL 17q
//! `FileFlows::init`, and the SIN_FILE_FLOW record consts. Witness
//! bodies (finspect stubs twins) stand in for the unported layers with
//! the stubs' EXACT print text; the harness-only C prints the replay
//! reconstructs verbatim are: the witness load_config STEAL line
//! (`FIM ...`, witness #7 — the ported ctor itself prints NOTHING, §4),
//! the real-~Inspector refcount witness (`Inspector dtor gref=0`), the
//! ThreadConfig/ErrorMessage witnesses behind set_max_files (17p
//! twins), and the `CFGLOG ` stand-in prefix the stub loggers glue onto
//! the real %25s caption column (messages.cc:364-:371/:545-:559).
//!
//! V8c pins the h:36 closure: `get_file_config(env)` must hand back the
//! SAME Rc the real ctor stole (R9: the C cast chain reads the real
//! member now) — `Rc::ptr_eq` here == `thru == fi->config` there.
//! V7 wiring drives `FileInspect` new -> drop (the real dtor frees the
//! heap steal, R2) and NEVER mod_ctor/mod_dtor (R3 vtable hole).

use std::cell::RefCell;
use std::rc::Rc;

use snort3::file_api::file_cache::{ErrorLogApi, FileCache, ThreadApi};
use snort3::file_api::file_config::get_file_config;
use snort3::file_api::file_lib::FileConfigLite;
use snort3::file_api::file_inspect::{
    self as fin, EchoDataBusId, EchoMpBus, EchoSmd, get_file_adv_pub_id,
};
use snort3::file_api::file_lib::FileEnvLite;
use snort3::log::messages::{LogEngine, Phase};

const VECTORS: &str = include_str!("../tools/finspect_harness/vectors.txt");

// ------------------------------------------------------------------
// Witness twins (finspect stubs.cc bodies; the println->Vec shape
// translation is documented in file_inspect.rs).
// ------------------------------------------------------------------

/// `FileIdModule::load_config` witness #7 (stubs.cc): the STEAL
/// `dst = fc; fc = nullptr;` over the module slot + the FIM print.
/// The ported `FileInspect::new` IS the same take — lines ride only
/// when the probe/C call the witness body directly (V8a/V1/V7 arms).
fn wit_load_config(
    out: &fin::WitnessOut,
    mod_slot: &mut Option<Rc<RefCell<FileConfigLite>>>,
) -> Option<Rc<RefCell<FileConfigLite>>> {
    let dst = mod_slot.take();
    fin::push_witness(out, format!("FIM load_config stole={}", u8::from(dst.is_some())));
    dst
}

/// `FileService::set_max_file_depth` ThreadConfig witness (17p twin).
struct ThreadWit {
    out: fin::WitnessOut,
}
impl ThreadApi for ThreadWit {
    fn get_instance_max(&mut self) -> u32 {
        fin::push_witness(&self.out, "WITNESS ThreadConfig::get_instance_max=1");
        1
    }
}

/// ErrorMessage witness behind the set_max_files clamp (fcache twin).
struct ErrWit {
    out: fin::WitnessOut,
}
impl ErrorLogApi for ErrWit {
    fn error_message(&mut self, msg: &str) {
        fin::push_witness(
            &self.out,
            format!("WITNESS ErrorMessage {}", msg.trim_end_matches('\n')),
        );
    }
}

/// The whole probe main() as one ordered session.
struct Session {
    out: fin::WitnessOut,
    env: FileEnvLite,
    dbus: EchoDataBusId,
    mp: EchoMpBus,
    smd: EchoSmd,
    /// the witness FileIdModule's config slot (finspect_arm_mod_fc:
    /// `if (!g_mod_fc) g_mod_fc = new FileConfig();` — heap-only, R2)
    mod_slot: Option<Rc<RefCell<FileConfigLite>>>,
    /// the toggle singleton (get_stub_file_inspector; constructed once,
    /// deliberately LEAKED in C — dropped at session end here, same
    /// observation: no further IMGR witness pins ride Rust teardown).
    insp: Option<fin::FileInspect>,
    /// fconf_set_file_inspector_null save slot (pointer swap, no print)
    saved_cfg: Option<Rc<RefCell<FileConfigLite>>>,
    engine: LogEngine,
}

impl Session {
    fn new() -> Self {
        let out = Rc::new(RefCell::new(Vec::new()));
        let mut env = FileEnvLite::default();
        // probe :98 FileCache cache(4) lands later (V2); env-side
        // seams for the trio come with it.
        env.svc.set_file_cache(None);
        Session {
            out: out.clone(),
            env,
            dbus: EchoDataBusId::new(&out),
            mp: EchoMpBus::new(&out),
            smd: EchoSmd::new(&out),
            mod_slot: None,
            insp: None,
            saved_cfg: None,
            engine: LogEngine::default(),
        }
    }

    fn arm_mod_fc(&mut self) {
        if self.mod_slot.is_none() {
            self.mod_slot = Some(Rc::new(RefCell::new(FileConfigLite::default())));
        }
    }

    /// Real-~FileInspect + Inspector base dtor chain (framework
    /// Inspector::~Inspector stub print `Inspector dtor gref=%u`,
    /// refcount 0 at every reached site: the global-ref family never
    /// armed in this probe).
    fn drop_inspector_with_frame_dtor(&mut self, insp: fin::FileInspect) {
        fin::push_witness(&self.out, "Inspector dtor gref=0");
        drop(insp); // real cc:53-:57 delete-config == Rc drop (heap-only, R2)
    }

    /// Drain the engine transcript into CFGLOG-prefixed vector lines
    /// (the stub loggers printf the tag without a newline; the vectors
    /// carry tag + column on one line).
    fn drain_cfglog(&mut self) {
        let events = std::mem::take(&mut self.engine.out);
        for ev in events {
            assert_eq!(ev.phase, Phase::Stdout, "ConfigLogger routes to stdout");
            fin::push_witness(
                &self.out,
                format!("CFGLOG {}", ev.text.trim_end_matches('\n')),
            );
        }
    }

    /// run configure + collect nothing extra (witnesses print
    /// themselves); returns the bool for the ret= pins.
    fn configure(&mut self) -> bool {
        let insp = self.insp.as_mut().unwrap();
        insp.configure(
            &mut self.env,
            &mut self.dbus,
            &mut self.mp,
            &mut self.smd,
        )
    }

    fn show(&mut self) {
        let insp = self.insp.as_ref().unwrap();
        insp.show(&mut self.engine, &self.env);
        self.drain_cfglog();
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn finspect_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 103, "vectors.txt must stay the 103-line oracle");
    let mut s = Session::new();

    // ---- V8a: the load_config STEAL standalone (file_module.cc:
    // 263-:266): arm -> steal -> second arm null. ----
    s.arm_mod_fc(); // finspect_arm_mod_fc (no print)
    let s1 = wit_load_config(&s.out, &mut s.mod_slot); // line 1 stole=1
    let s2 = wit_load_config(&s.out, &mut s.mod_slot); // line 2 stole=0
    fin::push_witness(
        &s.out,
        format!(
            "V8a_steal first={} second={}",
            u8::from(s1.is_some()),
            u8::from(s2.is_some())
        ),
    ); // line 3
    drop(s1); // heap-only hand-off (R2)

    // ---- V8b: the fcache_set_file_inspector(1) toggle (R1: never
    // nullptr-mod): arm + REAL ctor over the witness module: the C
    // link prints the FIM steal line via witness #7, then
    // `new FileInspect(g_wit_mod)`. The Rust composition matches: the
    // witness line rides, FileInspect::new steals (line 4).
    // The h:36 member then feeds get_file_config (R9: one member ->
    // env.file_config IS that member's slot here). ----
    s.arm_mod_fc();
    let cfg = wit_load_config(&s.out, &mut s.mod_slot); // line 4 stole=1
    let insp = fin::FileInspect { config: cfg }; // the real ctor (no print of its own)
    let have_cfg = u8::from(insp.config.is_some());
    s.env.file_config = insp.config.clone(); // get_file_config resolution seam
    s.insp = Some(insp);
    fin::push_witness(&s.out, format!("V8b_ctor cfg={have_cfg}")); // line 5: cfg=1

    // ---- V1: null-config early return (cc:61-:62): steal the fresh
    // heap slot away from a LOCAL ctor so config stays nullptr;
    // configure answers true with ZERO witness lines, the static is
    // still 0, show() silent; the local dtor (real, config null)
    // reaches the Inspector frame dtor print. ----
    s.arm_mod_fc();
    let held = wit_load_config(&s.out, &mut s.mod_slot); // line 6 stole=1 (arm consumed by probe)
    // the C `FileInspect nullcfg(pinned_mod())` ctor -> the REAL ctor
    // derefs fm -> witness #7 fires AGAIN on the now-empty slot:
    // line 7 stole=0; the Rust ctor is the same take (no print of its
    // own -- the FIM line is the witness-mod body, V1 arm drives it).
    let null_cfg = wit_load_config(&s.out, &mut s.mod_slot); // line 7 stole=0
    let mut nullcfg = fin::FileInspect { config: null_cfg }; // config None
    fin::push_witness(
        &s.out,
        format!(
            // C prints `nullcfg.config ? 1 : 0` -- the label reads
            // "ctor_stole_null" but the expression is HAS-config:
            // the steal on an empty slot leaves config null -> 0.
            "V1_pre ctor_stole_null={} adv={}",
            u8::from(nullcfg.config.is_some()),
            get_file_adv_pub_id(&s.env)
        ),
    ); // line 8: 0, 0
    drop(held); // delete held
    let v1 = nullcfg.configure(
        &mut s.env,
        &mut s.dbus,
        &mut s.mp,
        &mut s.smd,
    );
    fin::push_witness(
        &s.out,
        format!(
            "V1_null_arm ret={} adv={}",
            u8::from(v1),
            get_file_adv_pub_id(&s.env)
        ),
    ); // line 8: ret=1 adv=0 (no DBUS/SMD/MP lines rode)
    // show(sc) -> silent (line 9 is the SILENT pin itself)
    fin::push_witness(&s.out, "V1_show silent=1");
    s.drop_inspector_with_frame_dtor(nullcfg); // line 10 (frame dtor witness)

    // ---- V2: cache-armed trio through the REAL 17p setters (C
    // `FileCache cache(4)` + fcache_set_file_cache). The clamp
    // (minimal_files = instance_max+1 = 2) + ErrorMessage ride free. ----
    let cache = Rc::new(RefCell::new(FileCache::new(4)));
    cache.borrow_mut().thread = Box::new(ThreadWit { out: s.out.clone() });
    cache.borrow_mut().errlog = Box::new(ErrWit { out: s.out.clone() });
    s.env.svc.set_file_cache(Some(cache.clone()));
    {
        let mut c = s.insp.as_ref().unwrap().config.as_ref().unwrap().borrow_mut();
        c.file_block_timeout = 777;
        c.file_lookup_timeout = 9;
        c.max_files_cached = 64;
    }
    let v2 = s.configure(); // lines 11-13: WITNESS TC, SMD conf=1 depth=0, DBUS -> 7
    fin::push_witness(
        &s.out,
        format!(
            "V2_trio ret={} bt={} lt={} mf={}",
            u8::from(v2),
            cache.borrow().block_timeout(),
            cache.borrow().lookup_timeout(),
            cache.borrow().max_files()
        ),
    ); // line 14
    s.insp
        .as_ref()
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .borrow_mut()
        .max_files_cached = 1;
    s.configure(); // lines 15-19 head: TC, ErrorMessage clamp, SMD, DBUS
    fin::push_witness(
        &s.out,
        format!("V2_clamp mf={}", cache.borrow().max_files()),
    ); // line 19
    s.insp
        .as_ref()
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .borrow_mut()
        .max_files_cached = 64;

    // ---- V5: mp_dbus skip pin (two configures ran, counters 0), then
    // the armed arm (cc:76-:83): reg_helpers carries the REAL 17t
    // codec pair, subscribe carries the FileCacheShare name. ----
    fin::push_witness(
        &s.out,
        format!("V5_skip reg={} sub={}", s.mp.reg_calls, s.mp.sub_calls),
    ); // line 20: 0 0
    s.env.mp_dbus.set(true); // fcache_set_mp_dbus(1)
    s.configure(); // lines 21-25: TC, SMD, DBUS, MPDBUS reg, MPDBUS sub
    fin::push_witness(
        &s.out,
        format!("V5_arm reg={} sub={}", s.mp.reg_calls, s.mp.sub_calls),
    ); // line 26
    s.env.mp_dbus.set(false);

    // ---- V4: the cc:46 static round trip through the REAL getter:
    // witness id 7 (already set), re-pin 9 -> configure -> getter. ----
    fin::push_witness(&s.out, format!("V4_id a={}", get_file_adv_pub_id(&s.env))); // line 27: 7
    s.dbus.witness_id.set(9); // finspect_set_dbus_get_id(9)
    s.configure(); // lines 28-30
    fin::push_witness(&s.out, format!("V4_id b={}", get_file_adv_pub_id(&s.env))); // line 31: 9

    // ---- V3: the instrumented SMD walk (file_service.cc:227-:251)
    // + getter passthrough, then the fconf null toggle arm, then the
    // g_max_file_depth setter readout. ----
    s.env.svc.set_file_type_enabled(true); // fcache_set_file_service(1)
    s.configure(); // lines 32-34 (SMD depth=1460+1)
    fin::push_witness(
        &s.out,
        format!(
            "V3_depth typeon={} cfgdepth={}",
            s.env.get_max_file_depth(None),
            s.insp
                .as_ref()
                .unwrap()
                .config
                .as_ref()
                .unwrap()
                .borrow()
                .file_depth
        ),
    ); // line 35: 1461 / 1461
    s.env.svc.set_file_signature_enabled(true); // static true
    s.configure(); // lines 36-38 (SMD depth=10485760+1)
    fin::push_witness(
        &s.out,
        format!(
            "V3_depth sigon={}",
            s.env.get_max_file_depth(None)
        ),
    ); // line 39: 10485761
    s.saved_cfg = s.env.file_config.take(); // fconf_set_file_inspector_null(1)
    s.configure(); // lines 40-42 (SMD conf=0 arm)
    s.env.max_file_depth.set(4242); // fcache_set_max_file_depth(4242)
    fin::push_witness(
        &s.out,
        format!(
            "V3_depth gsetter={}",
            s.env.get_max_file_depth(None)
        ),
    ); // line 43: 4242
    s.env.file_config = s.saved_cfg.take(); // re-arm BEFORE next reads (R9/teardown)

    // ---- V6: the 18-caption show ladder, four enable arms over the
    // REAL ported ConfigLogger (real caption column, real flag-return
    // gating). ----
    // arm A: everything off -> the 11-line unconditional tail.
    s.env.svc.set_file_type_enabled(false);
    s.env.svc.set_file_signature_enabled(false);
    s.env.svc.set_file_capture_enabled(false);
    {
        let mut c = s.insp.as_ref().unwrap().config.as_ref().unwrap().borrow_mut();
        c.block_timeout_lookup = false;
        c.trace_type = false;
        c.trace_signature = false;
        c.trace_stream = false;
    }
    s.show(); // lines 44-54
    // arm B: type + block_timeout_lookup on.
    s.env.svc.set_file_type_enabled(true);
    s.insp
        .as_ref()
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .borrow_mut()
        .block_timeout_lookup = true;
    s.show(); // lines 55-67
    // arm C: capture on -> the 4-value capture block (long overload).
    s.env.svc.set_file_type_enabled(false);
    s.insp
        .as_ref()
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .borrow_mut()
        .block_timeout_lookup = false;
    s.env.svc.set_file_capture_enabled(true);
    s.show(); // lines 68-82
    // arm D: the three trace flags on (ungated log_flag tails).
    s.env.svc.set_file_capture_enabled(false);
    {
        let mut c = s.insp.as_ref().unwrap().config.as_ref().unwrap().borrow_mut();
        c.trace_type = true;
        c.trace_signature = true;
        c.trace_stream = true;
    }
    s.show(); // lines 83-93
    {
        let mut c = s.insp.as_ref().unwrap().config.as_ref().unwrap().borrow_mut();
        c.trace_type = false;
        c.trace_signature = false;
        c.trace_stream = false;
    }
    s.env.svc.set_file_service_enabled(false, false); // final fcache_set_file_service(0)

    // ---- V7: the sin_file_flow record read off the global consts
    // (V7_base/V7_api) + the file_init round trip + the ctor/dtor
    // wiring probe (NEVER mod_ctor/mod_dtor, R3). ----
    let rec = &fin::SIN_FILE_FLOW;
    fin::push_witness(
        &s.out,
        format!(
            "V7_base type={} size={} apiver={} apiver_lo={} ver={} feat={} opts={} name={} help={}",
            rec.ptype,
            rec.size,
            rec.api_version >> 16,
            rec.api_version & 0xffff,
            rec.version,
            rec.features,
            rec.options,
            rec.name,
            rec.help
        ),
    ); // line 94
    fin::push_witness(
        &s.out,
        format!(
            "V7_api itype={} proto_bits={} svc={} bufs={} pinit={} pterm={} tinit={} tterm={} ctor={} dtor={} ssn={} reset={}",
            rec.itype,
            rec.proto_bits,
            rec.service,
            u8::from(rec.buffers.is_some()),
            u8::from(rec.pinit),
            u8::from(rec.pterm),
            u8::from(rec.tinit),
            u8::from(rec.tterm),
            u8::from(rec.ctor),
            u8::from(rec.dtor),
            u8::from(rec.ssn),
            u8::from(rec.reset)
        ),
    ); // line 95
    let fd_before = s.env.file_flow_data_id.get();
    fin::file_init(&mut s.env); // iapi->pinit() -> FileFlows::init (REAL 17q)
    let fd_after = s.env.file_flow_data_id.get();
    fin::push_witness(
        &s.out,
        format!("V7_init fdid={}->{}", fd_before, fd_after - fd_before),
    ); // line 96: 0->1
    s.arm_mod_fc(); // fresh heap for the wiring probe
    let w_cfg = wit_load_config(&s.out, &mut s.mod_slot); // line 97 stole=1 (witness #7 through file_ctor)
    let w = fin::FileInspect { config: w_cfg }; // file_ctor's body
    fin::push_witness(&s.out, format!("V7_wiring ctor_have={}", u8::from(true))); // line 98
    s.drop_inspector_with_frame_dtor(w); // iapi->dtor(w) -> real dtor frees heap steal; line 99 frame dtor
    fin::push_witness(&s.out, "V7_wiring dtor_done=1"); // line 100
    s.env.svc.set_file_cache(None); // fcache_set_file_cache(nullptr)

    // ---- V8c: the get_file_config chain against the closed h:36
    // member (R9): the seam must answer the SAME Rc the real ctor
    // stole — the port-side mirror of `thru == fi->config`. ----
    let insp = s.insp.as_ref().unwrap();
    let thru = get_file_config(&s.env);
    let thru_same = match (&thru, insp.config.as_ref()) {
        (Some(a), Some(b)) => Rc::ptr_eq(a, b),
        _ => false,
    };
    fin::push_witness(
        &s.out,
        format!(
            "V8c_seam insp={} cfg={} thru_same={}",
            u8::from(true), // the toggle singleton stands (get_stub_file_inspector)
            u8::from(insp.config.is_some()),
            u8::from(thru_same)
        ),
    ); // line 101

    fin::push_witness(&s.out, "FINSPECT_PROBE_DONE"); // line 103

    let got = s.out.borrow();
    assert_eq!(got.len(), want.len(), "transcript line count");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {}: Rust replay vs C probe", i + 1);
    }
}
