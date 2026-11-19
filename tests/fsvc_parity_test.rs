//! Parity test for `src/file_api/file_service.{h,cc}` — row 17y.
//!
//! Ground truth: `tools/fsvc_harness/vectors.txt` (64 L, NEVER edited) —
//! the C transcript of file_service.{h,cc} driven by probe.cc (V1..V14;
//! the TU has ZERO TEST_CASEs and ZERO `#ifdef UNIT_TEST` fragments —
//! fsvc PLAN §1: probe vectors are the only oracles; the compiled C
//! probe re-ran this session and re-matched vectors.txt VERBATIM),
//! replayed here as ONE ordered session (fpolicy/finspect replay
//! shape: per-index assert_eq against the vectors line, want.len()==64).
//!
//! The REAL ported ladder runs end to end here (all bodies LANDED row
//! 17y in file_lib.rs `FileServiceLite`):
//!   V1  sizes/enum pins — the C sizes are the PROBE-PINNED literals
//!       (vectors:5; NEVER a Rust size_of on a ported type — the
//!       file_policy.rs C_SIZEOF_* rule). `dec=48` = sizeof
//!       FileService::decode_conf, harness-only (no DecodeConfig in
//!       src/ — the seam deviation, KNOWN DEVIATIONS row 17y); `def=2`
//!       rides the LIVE enum default ordinal (h:60 UNAVAILABLE);
//!       `spid=6` is a LIVE read through the REAL ProtocolReference
//!       add/find pair (target_based/snort_protocols.rs — the 17y
//!       real-cp witness parity).
//!   V2  the enable trio + REAL cascade (cc:199-:204) + the EXACT 2-OR
//!       is_file_service (cc:206-:209); V2b the capture-only drift arm
//!       -> svc=0 (the RETIRED 3-OR donor witness said 1 — PLAN R3;
//!       the Rust side was never drifted; the FIXACC static poke maps
//!       to the set_file_capture_enabled arm: the cascade hides the
//!       t=0,s=0,c=1 shape from the public API).
//!   V3  the clear-status 5-arm ladder (conf_present / max_procs /
//!       mp_dbus / cache-null / the pause Cell) + the pause-witness
//!       prints at the C reach positions (the freeze=0 pin = the
//!       cc:93-:94 || short-circuit BEFORE the cc:101 call — no
//!       pause_calls bump on arms 1-4) + the REAL FileCache::clear
//!       reports + the h:94 UNCHANGED contract + the cc:111 non-READY
//!       NO-FIRE arm + the READY empty zero-walk.
//!   V9  the reset() gate BOTH ways through the NEW get_inspector arm
//!       (InspectorManagerApi::get_inspector, default None — every
//!       frozen acquire/release twin stays byte-verbatim).
//!   V4  verify_reload FIRST (shadows 0 at load -> ReloadError x3
//!       through the ErrorLogApi::reload_error seam, the fmt strings
//!       VERBATIM cc:155/:160/:162 — the capture pair under the cc:157
//!       armed guard) + the UNKNOWN_PROTOCOL_ID re-arm through the
//!       REAL find + the conf-null arm (cc:149: reset STILL clears
//!       when the gate is closed).
//!   V5  post_init EXACTLY ONCE (gate-open reset -> the enables
//!       SURVIVE; MimeApi::init BEFORE the conf check — cc:120-:121
//!       order pin; the lazy FileCache::new + timeout pair cc:128-:134
//!       with ZERO IMGR churn (the cache builds contexts only on
//!       add); the capture pair -> FileCaptureFactory::init_capture
//!       over the landed statics + the shadow COPY; the proto arm
//!       cc:143 lands find again, idempotent). V5b the cc:127 lazy-
//!       cache KEEP (Rc ptr-equality) + the empty READY clear pair.
//!   V6  verify_reload SECOND pass: post_init COPIED the shadows ->
//!       ZERO reload lines (cc:154 NEVER assigns — copy-vs-compare).
//!   V8  the REAL get_max_file_depth ladder (config 1460 / conf-null
//!       -1 / the fc-ARG wins -1) + the R4 drift (the armed
//!       env.max_file_depth passthrough shadow INERT against the real
//!       body) + the REAL set ladder (type copy + the "extra byte"
//!       ++, sig-gt raise + ++, both-off neg stays, cc:245 guard).
//!   V10 collect_cache_usage over the landed snapshot Builder: the
//!       null-cache return, the entries>0 gate, the "File cache
//!       entries" counter name + Value::U64 readback, the append on a
//!       second call.
//!   V11 close: the ONLY-owner cache drop (the driver `posted` alias
//!       was already gone — the Rc drop fires the IMGR release AT the
//!       C delete position, the R2 new/delete pair with post_init),
//!       then MimeApi::exit (cc:179), then the landed capture exit
//!       drain (cc:180; the ONE init pair V5->V11, single-thread
//!       model, silent).
//!   V12 thread_init/term -> the landed file_stats calloc/free cycle.
//!   V13 the REAL free get_file_processed_size (the 17q file_flows.rs
//!       body — the retired verbatim-copy witness is GONE; cite only)
//!       three arms over the REAL FileFlows + cache + FileContext
//!       stack: no-fflows 0 / no current context 0 / update_file_size
//!       (7, MIDDLE) -> 7, with the NetPol + IMGR + curbkt (GET_
//!       CURRENT_PACKET macro-arg) witness pairs at the C positions.
//!   V14 init() -> the landed FileFlows::init -> the counter lands 1.
//!
//! R2/heap posture: post_init ONCE, close ONCE, the same cache; the
//! driver never holds an owning alias into the svc cache past V10 (the
//! R2 pin — close owns the delete). The capture writer is the landed
//! single-thread model (init flag + exit drain; no OS thread ever
//! exists — the 17s deviation, fcap PLAN :794-:796 order rule).
//!
//! Witness posture (PLAN §2.2 NEW/KEEP): the driver twins print the
//! donor formats BYTE-VERBATIM — `WITNESS packet_threads_fully_
//! paused=<v>` (only on a real predicate reach), `WITNESS
//! MimeSession::init|exit`, `IMGR get_inspector file_inspect
//! usage=<Module::GLOBAL=0 -> module.h:216> -> inspector|null`,
//! `WITNESS ReloadError ...` (resident stubs.cc:123 KEEP), `IMGR
//! acquire/release`, `WITNESS get_network_policy` + `POLICY
//! base_file_policy -> stub` (the §2.2 NO-retirement verdict pair),
//! `DE get_current_packet have=0` (never-armed packet). Line 1 `FIM
//! load_config stole=1` is the harness finspect_arm_mod_fc resolve arm
//! (the get_file_config resolution fixture — NOT a FileService line);
//! no "FileInspect ctor" line exists in these 64 (the 17y fsvc shape
//! arms the latched inspector silently).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use snort3::file_api::file_api::{
    FileCacheClearResult, FileCacheClearStatus, FilePolicyApi, FilePolicyHandle, SNORT_FILE_MIDDLE,
};
use snort3::file_api::file_cache::{
    CacheFlow, CurrentPacketApi, ErrorLogApi, FileCache, FileConfigView, FileHashKey, InspectorApi,
    InspectorManagerApi, PacketView,
};
use snort3::file_api::file_flows::{get_file_processed_size, FileFlows};
use snort3::file_api::file_lib::{
    FileConfigLite, FileContext, FileEnvLite, FileServiceLite, MimeApi, NetworkPolicySeam,
};
use snort3::file_api::file_stats::FileCounts;
use snort3::utils::stats::snapshot::{Builder, Snapshot, Value};

const VECTORS: &str = include_str!("../tools/fsvc_harness/vectors.txt");

// probe-pinned literals (vectors:5 `rc=16 st=1 rs=24 dec=48` — NEVER
// Rust size_of on a ported type; C layout homes: FileCacheClearReport
// 16 / FileCacheClearStatus 1 (enum-class u8) / FileCacheClearResult
// 24 (report 16 + u8 + 7 pad, h:56-:62) / DecodeConfig 48 harness-
// only — the decode_conf seam deviation, KNOWN DEVIATIONS row 17y).
const C_SIZEOF_CLEAR_REPORT: usize = 16;
const C_SIZEOF_CLEAR_STATUS: usize = 1;
const C_SIZEOF_CLEAR_RESULT: usize = 24;
const C_SIZEOF_DECODE_CONF: usize = 48;

type Out = Rc<RefCell<Vec<String>>>;

fn push(out: &Out, line: impl Into<String>) {
    out.borrow_mut().push(line.into());
}

/// `fcache_set_file_service(int on)` witness body VERBATIM (the donor
/// arm KEPT at stubs.cc:735-:743 — against the real statics it now
/// writes through the REAL fields): sets the TYPE static; the off arm
/// clears signature AND capture. V8 calls it with 0; V13 with 1 (the
/// get_file_flows creation switch, file_flows.cc:143).
fn wit_set_file_service(env: &mut FileEnvLite, on: bool) {
    env.svc.set_file_type_enabled(on); // stubs.cc:737
    if !on {
        // stubs.cc:738-:742
        env.svc.set_file_signature_enabled(false);
        env.svc.set_file_capture_enabled(false);
    }
}

/// The pause witness wrapper over the REAL status ladder: the C
/// `main_packet_threads_fully_paused()` (armable, stubs.cc NEW17y)
/// prints WHENEVER the ladder reaches it — so the driver print fires
/// iff `pause_calls` actually moved (arms 1-4 return before the
/// cc:99-:101 step: the V3_ladder `freeze=0` count pin, silent here).
fn wit_status(
    env: &FileEnvLite,
    out: &Out,
    conf_present: bool,
    max_procs: u32,
) -> FileCacheClearStatus {
    let before = env.svc.pause_calls.get();
    let st = FileServiceLite::get_file_cache_clear_status(env, conf_present, max_procs);
    if env.svc.pause_calls.get() != before {
        push(
            out,
            format!(
                "WITNESS packet_threads_fully_paused={}",
                u8::from(env.svc.packet_threads_fully_paused.get())
            ),
        );
    }
    st
}

/// The clear_file_cache wrapper: C's body runs get_file_cache_clear_
/// status FIRST (cc:109 — the predicate witness print lands THERE,
/// before the clear walk's slot releases) — the driver reaches the
/// same order by running the printed status step (wit_status) and
/// then the REAL clear body (whose internal re-evaluation is silent,
/// same args, same ladder — the pause_calls count is not observed
/// after the freeze pin).
fn wit_clear(
    env: &FileEnvLite,
    out: &Out,
    conf_present: bool,
    max_procs: u32,
) -> FileCacheClearResult {
    wit_status(env, out, conf_present, max_procs); // the cc:109 -> cc:99-:104 witness step
    FileServiceLite::clear_file_cache(env, conf_present, max_procs)
}

/// The harness FileInspect witness (its `config` = a FileConfigView —
/// the 17q single-view graft; read nowhere in these 64 lines).
struct StubInspector {
    cfg: Rc<RefCell<FileConfigView>>,
}
impl InspectorApi for StubInspector {
    fn config(&self) -> Rc<RefCell<FileConfigView>> {
        self.cfg.clone()
    }
}

/// The donor IMGR trio (stubs.cc:445-:466 acquire/release — KEEP) +
/// NEW17y NEW-4 get_inspector (stubs.cc new witness: the reset() gate
/// reader, armed by fsvc_get_inspector_arm; `usage=0` ==
/// Module::GLOBAL, framework/module.h:216 — before the print).
struct ImgrWit {
    out: Out,
    armed: Rc<RefCell<Option<Rc<StubInspector>>>>,
    get_arm: Rc<Cell<bool>>,
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
    fn get_inspector(&mut self, name: &str, usage: u32) -> Option<Rc<dyn InspectorApi>> {
        let lit = self.get_arm.get() && self.armed.borrow().is_some();
        push(
            &self.out,
            format!(
                "IMGR get_inspector {name} usage={usage} -> {}",
                if lit { "inspector" } else { "null" }
            ),
        );
        if lit {
            self.armed
                .borrow()
                .as_ref()
                .map(|a| a.clone() as Rc<dyn InspectorApi>)
        } else {
            None
        }
    }
}

/// NEW17y NEW-2/3: the MimeSession print pair (stubs.cc NEW17y; the
/// mime row stays queued — NO mime body; the pair pins the cc:121-
/// before-conf-check init and the cc:179 close exit).
struct MimeWit {
    out: Out,
}
impl MimeApi for MimeWit {
    fn init(&mut self) {
        push(&self.out, "WITNESS MimeSession::init");
    }
    fn exit(&mut self) {
        push(&self.out, "WITNESS MimeSession::exit");
    }
}

/// The RESIDENT ReloadError witness (stubs.cc:123 — KEEP per PLAN
/// §2.2; the fmt strings carry their own trailing \n in C — the
/// vectors line ends after it).
struct ErrLogWit {
    out: Out,
}
impl ErrorLogApi for ErrLogWit {
    fn error_message(&mut self, _msg: &str) {}
    fn reload_error(&mut self, msg: &str) {
        push(
            &self.out,
            format!("WITNESS ReloadError {}", msg.trim_end_matches('\n')),
        );
    }
}

/// The NetworkPolicy witness pair (stubs.cc:697-:701 — the §2.2
/// NO-retirement answer; the V13 get_file_flows creation reaches it,
/// file_flows.cc:150).
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

/// StubFilePolicy twin (stubs.cc:360-:370 shape — KEEP, R5 no T-def
/// collision; the lookups stay UNREACHED in this probe, the twin only
/// feeds the pinned handle through NetPolWit).
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

/// The GET_CURRENT_PACKET witness (the donor DE arm — the probe never
/// arms a current packet: `DE get_current_packet have=0`; the macro
/// argument is evaluated at every reached FILE_DEBUG site, level gate
/// or not — env.curbkt mirrors that exactly).
struct CurPktWit {
    out: Out,
}
impl CurrentPacketApi for CurPktWit {
    fn get_current_packet(&mut self) {
        push(&self.out, "DE get_current_packet have=0");
    }
}

/// The whole probe main() as one ordered session (probe.cc:109-:435).
#[test]
fn fsvc_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 64, "vectors.txt must stay the 64-line oracle");
    let out: Out = Rc::new(RefCell::new(Vec::new()));

    // ---- probe setup (probe.cc:111-:122) ----
    let armed: Rc<RefCell<Option<Rc<StubInspector>>>> = Rc::new(RefCell::new(None));
    let get_arm = Rc::new(Cell::new(false));
    let conf_view: Rc<RefCell<FileConfigView>> = Rc::new(RefCell::new(FileConfigView::default()));

    let mut env = FileEnvLite::default();
    let imgr = Rc::new(RefCell::new(
        Box::new(ImgrWit {
            out: out.clone(),
            armed: armed.clone(),
            get_arm: get_arm.clone(),
        }) as Box<dyn InspectorManagerApi>,
    ));
    env.imgr = imgr.clone();
    env.curpkt = Box::new(CurPktWit { out: out.clone() });
    env.mime = Rc::new(RefCell::new(Box::new(MimeWit { out: out.clone() })));
    env.network_policy = Some(Rc::new(RefCell::new(NetPolWit {
        out: out.clone(),
        handle: FilePolicyHandle::new_boxed(Box::new(PolicyStub)), // ref 1 at "new"
    })));
    // fcache_enable_fake_clock(1) == the pinned fake packet clock (the
    // C t=100.0 arm): silent here — no duration line is emitted.
    // The REAL config chain (17w R2): ONE heap FileConfigLite, the
    // default field table, resolved through get_file_config.
    let cfg: Rc<RefCell<FileConfigLite>> = Rc::new(RefCell::new(FileConfigLite::default()));
    env.file_config = Some(cfg.clone());

    // The harness proto_ref (probe.cc:120-:122): REAL ProtocolReference
    // ctor (unknown/ip/icmp/tcp/udp/file = 0..5) + the literal
    // probe add("file_id") through the REAL add body -> 6.
    let spid_file_id = env.proto_ref.borrow_mut().add("file_id") as i32;

    // finspect_arm_mod_fc(); fcache_set_file_inspector(1): the harness
    // load_config STEAL resolve arm (line 1 — fixture witness, NOT a
    // FileService line; the 17y shape arms the latch WITHOUT the
    // finspect ctor print — the vectors have no `FileInspect ctor`
    // line, so the Rust latch is silent here).
    push(&out, "FIM load_config stole=1"); // line 1
    *armed.borrow_mut() = Some(Rc::new(StubInspector {
        cfg: conf_view.clone(),
    }));

    // ---- V1 (probe.cc:124-:139): the layout/enum pins, the h:60
    // default init, the REAL find seed. ----
    {
        // `FileCacheClearResult r;` -> C's in-class default member
        // inits (h:60 UNAVAILABLE + h:123/:124 zeroed report) — the
        // Rust enum Default mirrors h:60 exactly.
        let r = FileCacheClearResult::default();
        push(
            &out,
            format!(
                "V1_sizes rc={} st={} rs={} dec={} def={} spid={}",
                C_SIZEOF_CLEAR_REPORT,
                C_SIZEOF_CLEAR_STATUS,
                C_SIZEOF_CLEAR_RESULT,
                C_SIZEOF_DECODE_CONF,
                r.status as u8, // (int)r.status -> UNAVAILABLE ordinal (LIVE)
                spid_file_id,
            ),
        ); // line 2
        push(
            &out,
            format!(
                "V1_enum r={} m={} u={} n={} b={}",
                FileCacheClearStatus::Ready as u8,
                FileCacheClearStatus::Multiprocess as u8,
                FileCacheClearStatus::Unavailable as u8,
                FileCacheClearStatus::NotInitialized as u8,
                FileCacheClearStatus::PacketThreadsBusy as u8,
            ),
        ); // line 3
    }

    // ---- V2 (probe.cc:141-:164): the pre-init static read (R1
    // zero-init arm), the enable trio + the REAL cascade (cc:203 re-
    // signs), the svc 2-OR true side; then V2b: the capture-only arm
    // through the FIXACC-public setter — the ONLY way to reach
    // t=0,s=0,c=1 (the public API cascades signature ON). REAL 2-OR
    // -> svc=0; the RETIRED donor 3-OR witness would have said 1. ----
    {
        wit_set_file_service(&mut env, false); // fcache_set_file_service(0)
        let pre = u8::from(env.svc.is_file_service_enabled()); // R1: zero-init .bss read
        env.svc.enable_file_type(); // cc:189-:192
        let t = u8::from(env.svc.is_file_type_id_enabled());
        env.svc.enable_file_signature(); // cc:194-:197
        let s = u8::from(env.svc.is_file_signature_enabled());
        env.svc.enable_file_capture(); // cc:199-:204 (capture + cascade)
        let c = u8::from(env.svc.is_file_capture_enabled());
        let casc = u8::from(env.svc.is_file_signature_enabled()); // -> 1 (:203)
        let svc = u8::from(env.svc.is_file_service_enabled());
        push(
            &out,
            format!("V2_enable pre={pre} t={t} s={s} c={c} casc={casc} svc={svc}"),
        ); // line 4
        wit_set_file_service(&mut env, false); // all three off
        env.svc.set_file_capture_enabled(true); // FIXACC direct-static arm (probe.cc:159)
        push(
            &out,
            format!(
                "V2b_drift c={} svc={}",
                u8::from(env.svc.is_file_capture_enabled()),
                u8::from(env.svc.is_file_service_enabled()) // 1 0 — the REAL 2-OR (cc:208)
            ),
        ); // line 5
        env.svc.set_file_capture_enabled(false); // probe restore
    }

    // ---- V3 (probe.cc:166-:232): the 5-arm ladder + pause-both-ways
    // + the REAL clear reports + the contract pins, over a populated
    // BLOCK-LOCAL cache (the svc static null at entry; post_init later
    // sees the true null — R2 pin). The block cache rides an Rc +
    // RefCell through the donor fcache_set_file_cache arm (the C
    // stack-object + raw-pointer pair, 17p convention). ----
    {
        env.svc.packet_threads_fully_paused.set(true); // fsvc_set_paused(1) (silent — only reaches print when consulted)
        let mut cache = FileCache::new(16); // `FileCache cache(16)`
        cache.imgr = imgr.clone(); // the donor cache carries the manager (add's new-FileContext trio)
        let cache = Rc::new(RefCell::new(cache));
        env.svc.set_file_cache(Some(cache.clone())); // fcache_set_file_cache(&cache) :639

        let mut counts = FileCounts::default();
        let mut cf = false;
        let mut ce = 0i64;
        let k1 = FileHashKey {
            file_id: 11,
            ..Default::default()
        }; // FileHashKey k1 {}; file_id = 11
        let k2 = FileHashKey {
            file_id: 12,
            ..Default::default()
        };
        // cache.add(k1/k2, 60, cf, ce): each MISS -> new FileContext ->
        // acquire x2 (the armed latch -> "-> inspector" lines 6-7).
        cache
            .borrow_mut()
            .add(&k1, 60, &mut cf, &mut ce, false, &mut counts);
        cache
            .borrow_mut()
            .add(&k2, 60, &mut cf, &mut ce, false, &mut counts);
        let e_pop = cache.borrow_mut().get_num_entries();

        // arms 1-4: ZERO predicate reaches (freeze=0 across them).
        let st_unavail = wit_status(&env, &out, false, 1); // fsvc_set_conf_null(1) cc:89-:91
        let pc0 = env.svc.pause_calls.get();
        let st_multi = wit_status(&env, &out, true, 2); // sc->max_procs = 2, cc:93
        env.mp_dbus.set(true); // fcache_set_mp_dbus(1), cc:94
        let st_dbus = wit_status(&env, &out, true, 1);
        env.mp_dbus.set(false);
        let freeze = env.svc.pause_calls.get() - pc0; // the || short-circuit: 0
        env.svc.set_file_cache(None); // cc:96-:97 NOT_INITIALIZED
        let st_notinit = wit_status(&env, &out, true, 1);
        env.svc.set_file_cache(Some(cache.clone())); // re-arm
        env.svc.packet_threads_fully_paused.set(false); // fsvc_set_paused(0) -> reaches the predicate: print 0 (line 8)
        let st_busy = wit_status(&env, &out, true, 1);
        let e_unch = cache.borrow_mut().get_num_entries(); // h:94 contract check
        env.svc.packet_threads_fully_paused.set(true); // fsvc_set_paused(1) -> print 1 (line 9)
        let st_ready = wit_status(&env, &out, true, 1);
        push(
            &out,
            format!(
                "V3_ladder unavail={} multi={} dbus={} freeze={} notinit={} busy={} ready={}",
                st_unavail as u8,
                st_multi as u8,
                st_dbus as u8,
                freeze,
                st_notinit as u8,
                st_busy as u8,
                st_ready as u8,
            ),
        ); // line 10
        push(
            &out,
            format!("V3_unchanged same={}", u8::from(e_unch == e_pop)),
        ); // line 11

        // READY clear (wit_clear: the cc:109 witness step -> print 1
        // line 12 — THEN the clear walk's slot releases -> IMGR
        // release x2 at the C delete positions (free_user_data,
        // file_cache.rs:909-:912), lines 13-14).
        let clr = wit_clear(&env, &out, true, 1);
        push(
            &out,
            format!(
                "V3_clear st={} freed={} rem={} entries={}",
                clr.status as u8,
                clr.report.freed,
                clr.report.remaining,
                cache.borrow_mut().get_num_entries(),
            ),
        ); // line 15

        // the NON-READY clear (the cc:111 guard): re-pop (acquire x2,
        // lines 16-17), unpaused -> r2 BUSY: the NO-FIRE arm (pred
        // print 0 line 18, report default, the entries stay kept=2);
        // re-paused -> r3 READY clears the SAME two entries (pred
        // print 1 line 19 + release x2 lines 20-21).
        let mut cf = false;
        let mut ce = 0i64;
        cache.borrow_mut().add(&k1, 60, &mut cf, &mut ce, false, &mut counts);
        cache.borrow_mut().add(&k2, 60, &mut cf, &mut ce, false, &mut counts);
        env.svc.packet_threads_fully_paused.set(false); // fsvc_set_paused(0)
        let r2 = wit_clear(&env, &out, true, 1); // line 18 print
        let kept = cache.borrow_mut().get_num_entries();
        env.svc.packet_threads_fully_paused.set(true); // fsvc_set_paused(1)
        let r3 = wit_clear(&env, &out, true, 1); // line 19 print + releases 20-21
        push(
            &out,
            format!(
                "V3_busyarm st={} freed={} kept={} then st={} freed={} empty={}",
                r2.status as u8,
                r2.report.freed,
                kept,
                r3.status as u8,
                r3.report.freed,
                cache.borrow_mut().get_num_entries(),
            ),
        ); // line 22
        // READY on the already-empty cache: the zero walk (print 1,
        // line 23 — no contexts -> no release lines).
        let r4 = wit_clear(&env, &out, true, 1);
        push(
            &out,
            format!("V3_empty st={} freed={}", r4.status as u8, r4.report.freed),
        ); // line 24
        // R2 PIN: fcache_set_file_cache(nullptr) — the real static
        // never dangles past the block's C stack object (the Rust
        // block cache drops at scope end with ZERO residual contexts:
        // both clears released every slot, verified against the
        // vectors gap 24->25).
        env.svc.set_file_cache(None);
    }

    // ---- V9 (probe.cc:234-:253): the reset() gate BOTH ways
    // (cc:66-:74). CLOSED (arm 0): -> null (line 25), the statics
    // CLEAR. OPEN (arm 1 + latch): -> inspector (line 27), reset
    // returns at cc:68, the statics SURVIVE (the upstream order that
    // feeds the V4 capture guard and the V5 capture arm). ----
    {
        wit_set_file_service(&mut env, false);
        env.svc.enable_file_type();
        env.svc.enable_file_signature();
        FileServiceLite::reset(&env); // -> null print (line 25)
        push(
            &out,
            format!(
                "V9_clear t={} s={}",
                u8::from(env.svc.is_file_type_id_enabled()),
                u8::from(env.svc.is_file_signature_enabled())
            ),
        ); // line 26
        get_arm.set(true); // fsvc_get_inspector_arm(1)
        env.svc.enable_file_type();
        env.svc.enable_file_signature();
        FileServiceLite::reset(&env); // -> inspector (line 27): gate OPEN, no clear
        push(
            &out,
            format!(
                "V9b_gate t={} s={}",
                u8::from(env.svc.is_file_type_id_enabled()),
                u8::from(env.svc.is_file_signature_enabled())
            ),
        ); // line 28
    }

    // ---- V4 (probe.cc:255-:285): the verify_reload FIRST pass. The
    // gate is OPEN (V9b left it armed) so reset returns at cc:68 ->
    // the enables SURVIVE -> the cc:157 file_capture_enabled guard is
    // TRUE -> the ReloadError x3 through the RESIDENT sink (shadows
    // are 0 at load: the max drift + the capture pair), then the
    // UNKNOWN_PROTOCOL_ID re-arm answers REAL find("file_id") = 6
    // (cc:165-:168). ----
    {
        let mut err = ErrLogWit { out: out.clone() };
        cfg.borrow_mut().max_files_cached = 8; // cfg->max_files_cached = 8 (shadow drift: 0 != 8)
        env.svc.enable_file_capture(); // t+s+c lit (the cascade)
        cfg.borrow_mut().capture_memcap = 1; // shadow drift
        cfg.borrow_mut().capture_block_size = 32_768; // shadow drift
        cfg.borrow_mut().snort_protocol_id =
            0; // UNKNOWN_PROTOCOL_ID
        FileServiceLite::verify_reload(&mut env, &mut err); // -> inspector (line 29, reset no-op) + lines 30-32
        push(
            &out,
            format!(
                "V4_reload t={} spid={}",
                u8::from(env.svc.is_file_type_id_enabled()),
                cfg.borrow().snort_protocol_id
            ),
        ); // line 33
        // The conf-null arm (cc:149-:152): the inspector slot NULLed
        // -> get_file_config answers null -> EARLY RETURN before the
        // sc deref — but reset RAN FIRST and the gate is closed ->
        // the statics clear (t drops); spid STAYS in the config (cc:149
        // precedes the cc:165 re-arm).
        get_arm.set(false); // fsvc_get_inspector_arm(0)
        let saved_cfg = env.file_config.take(); // fconf_set_file_inspector_null(1)
        FileServiceLite::verify_reload(&mut env, &mut err); // -> null print (line 34), ZERO error lines
        env.file_config = saved_cfg; // fconf_set_file_inspector_null(0)
        push(
            &out,
            format!(
                "V4c_nullconf t={} spid={}",
                u8::from(env.svc.is_file_type_id_enabled()),
                cfg.borrow().snort_protocol_id
            ),
        ); // line 35
    }

    // ---- V5 (probe.cc:287-:308): post_init EXACTLY ONCE. Gate re-
    // armed (the reset early-returns -> the enables SURVIVE into the
    // cc:136 capture arm), the MimeSession::init print BEFORE any
    // conf check (cc:120-:121 pinned), the lazy cache NEW(conf->
    // max_files_cached = 8) + block/lookup timeouts (cc:128-:134,
    // ZERO IMGR churn — the cache creates contexts on add only), the
    // capture pair -> the landed FileCapture::init (REAL factory;
    // R9: the ONE init pair, closed by the real close at V11) + the
    // shadow COPY, then the proto arm cc:143 lands find again
    // (idempotent, spid 6). ----
    {
        get_arm.set(true); // fsvc_get_inspector_arm(1)
        env.svc.enable_file_capture(); // re-arm the cascade (t stays 0 — V4c cleared it)
        FileServiceLite::post_init(&mut env); // -> inspector (line 36) then WITNESS MimeSession::init (line 37)
        let svc_cache = env.svc.get_file_cache();
        push(
            &out,
            format!(
                "V5_post cache={} spid={} t={} c={}",
                u8::from(svc_cache.is_some()),
                cfg.borrow().snort_protocol_id,
                u8::from(env.svc.is_file_type_id_enabled()),
                u8::from(env.svc.is_file_capture_enabled())
            ),
        ); // line 38
        get_arm.set(false); // fsvc_get_inspector_arm(0)
        // V5b: the cc:127 lazy-cache KEEP — the identity survives a
        // READY status/clear pair on the FRESH (empty) cache (pred
        // print 1, line 39; zero walk = no release lines).
        let r = wit_clear(&env, &out, true, 1);
        let re = env.svc.get_file_cache();
        let same = match (&svc_cache, &re) {
            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
            _ => false,
        };
        push(
            &out,
            format!(
                "V5b_keep st={} freed={} same={}",
                r.status as u8,
                r.report.freed,
                u8::from(same)
            ),
        ); // line 40
    }

    // ---- V6 (probe.cc:310-:320): the verify_reload SECOND pass:
    // post_init COPIED the shadows (cc:131/:140-:141) -> ZERO reload-
    // error lines (cc:154 NEVER assigns — the copy-vs-compare pin);
    // the gate is closed here so the enables CLEAR (t=0) yet spid
    // STAYS (cc:165 false on the armed find result 6). -> null print
    // (line 41). ----
    {
        let mut err = ErrLogWit { out: out.clone() };
        FileServiceLite::verify_reload(&mut env, &mut err); // -> null (41), no error lines
        push(
            &out,
            format!(
                "V6_clean t={} spid={}",
                u8::from(env.svc.is_file_type_id_enabled()),
                cfg.borrow().snort_protocol_id
            ),
        ); // line 42
    }

    // ---- V8 (probe.cc:322-:351): the depth ladders (cc:211-:252).
    // The fcache g_max_file_depth shadow arm (env.max_file_depth, the
    // passthrough seam) is INERT against the REAL getter (R4); the
    // fc-ARG arm wins (cc:215). ----
    {
        cfg.borrow_mut().file_depth = 1460; // the type default pin
        env.max_file_depth.set(-7); // INERT shadow (R4 — fcache_set_max_file_depth)
        let ddef = FileServiceLite::get_max_file_depth(&env, None); // answers the CONFIG 1460
        let saved_cfg = env.file_config.take(); // fconf_set_file_inspector_null(1): conf-null cc:217-:219
        let dnull = FileServiceLite::get_max_file_depth(&env, None);
        env.file_config = saved_cfg; // restore
        env.max_file_depth.set(-9); // still inert
        let fc: Rc<RefCell<FileConfigLite>> = Rc::new(RefCell::new(FileConfigLite::default()));
        fc.borrow_mut().file_depth = -5; // `FileConfig fc; fc.file_depth = -5` — the fc-ARG WINS (cc:215)
        let dneg = FileServiceLite::get_max_file_depth(&env, Some(&fc));
        push(
            &out,
            format!("V8_get def={ddef} null={dnull} fcneg={dneg}"),
        ); // line 43
        wit_set_file_service(&mut env, false);
        env.svc.enable_file_type(); // the type-on arm cc:234-:237
        cfg.borrow_mut().file_type_depth = 1460;
        cfg.borrow_mut().file_signature_depth = 20;
        cfg.borrow_mut().file_depth = 7;
        FileServiceLite::set_max_file_depth(&env); // 1460 copy then cc:247 ++
        push(&out, format!("V8_set type={}", cfg.borrow().file_depth)); // line 44: 1461
        wit_set_file_service(&mut env, false);
        env.svc.enable_file_signature(); // the sig-gt arm cc:239-:243
        cfg.borrow_mut().file_depth = 7;
        FileServiceLite::set_max_file_depth(&env); // 20 > 7 -> 20 then ++
        push(&out, format!("V8_set2 sig={}", cfg.borrow().file_depth)); // line 45: 21
        wit_set_file_service(&mut env, false); // both off: the neg STAYS (cc:245 guard)
        cfg.borrow_mut().file_depth = -5;
        FileServiceLite::set_max_file_depth(&env);
        push(&out, format!("V8_set3 neg={}", cfg.borrow().file_depth)); // line 46: -5
    }

    // ---- V10 (probe.cc:353-:378): collect_cache_usage (cc:76-:84)
    // over the landed snapshot inlines (ZERO stats witnesses — the
    // §0.4 residue class). The C `stats::Counter` VALUE readback +
    // get_name ride the landed snapshot.rs Counter. NOTE the arm
    // order: capture the post_init cache ptr BEFORE nulling the real
    // static (the null-cache arm), then re-arm the SAME cache — the
    // row owns it (deleted by the V11 close, the R2 pair): the local
    // alias drops at block end while the svc static keeps the Rc.
    // The Builder RECEIVER arg the port carries mirrors the C
    // `builder.counter(...)` call shape — the snapshot.h:125 static
    // NEVER reads it (measured: zero stats symbols in the row
    // residue), so the replay passes a same-type builder over a
    // throwaway snapshot while the observable Group rides the first
    // one (the C probe's counters live in group.counters exactly
    // like this). ----
    {
        let mut snap = Snapshot::default();
        let mut b = Builder::new(&mut snap);
        let sec = b.section("file_api"); // C: b.section("file_api")
        let grp = Builder::group(sec, "File Cache"); // C: stats::Builder::group(sec, ...)

        let posted = env.svc.get_file_cache().expect("the post_init cache"); // FileCache* svc_cache = ...
        env.svc.set_file_cache(None); // fcache_set_file_cache(nullptr)
        FileServiceLite::collect_cache_usage(&env, grp); // cc:78 !file_cache return
        push(&out, format!("V10_null counters={}", grp.counters.len())); // line 47
        env.svc.set_file_cache(Some(posted.clone())); // re-arm the SAME cache
        let mut counts = FileCounts::default();
        let mut cf = false;
        let mut ce = 0i64;
        let k = FileHashKey {
            file_id: 77,
            ..Default::default()
        };
        posted.borrow_mut().add(&k, 60, &mut cf, &mut ce, false, &mut counts); // 1 entry -> acquire (line 48)
        FileServiceLite::collect_cache_usage(&env, grp); // cc:82-:83 counter
        let ctr = &grp.counters[0];
        push(
            &out,
            format!(
                "V10_ctr counters={} name={} v={}",
                grp.counters.len(),
                ctr.get_name(),
                match &ctr.value {
                    Value::U64(v) => *v,
                    _ => 0,
                }
            ),
        ); // line 49
        FileServiceLite::collect_cache_usage(&env, grp); // the 2nd call -> +1
        push(&out, format!("V10_twice counters={}", grp.counters.len())); // line 50
    } // `posted` drops HERE (non-owning alias gone — the svc static keeps the sole owner for the V11 delete; R2)

    // ---- V11 (probe.cc:380-:388): close (cc:171-:181): the ONLY-
    // owner delete + null (`delete file_cache` cc:175 — the Rc drop
    // fires the IMGR release for the 1 live slot context AT this
    // point, line 51); MimeSession::exit (cc:179 — the witness print,
    // line 52); FileCapture::exit (cc:180 — the landed drain-then-
    // flag body joins the V5-init writer model, silent, idempotent
    // after). ----
    {
        let had = u8::from(env.svc.get_file_cache().is_some()); // `int had = get_file_cache() ? 1 : 0`
        FileServiceLite::close(&mut env); // the cache drop -> the release line 51, then Mime exit line 52
        let after = u8::from(env.svc.get_file_cache().is_some());
        push(&out, format!("V11_close had={had} after={after}")); // line 53
    }

    // ---- V12 (probe.cc:390-:396): thread_init/thread_term (cc:183-
    // :187 brace-on-line) -> the REAL file_stats calloc/free cycle
    // (the landed file_stats.rs:180/:185 model — silent, one clean
    // pass; the file_stats witness hook file_stats_init/term pair). ----
    {
        FileServiceLite::thread_init(&mut env);
        FileServiceLite::thread_term(&mut env);
        push(&out, "V12_cycle done=1"); // line 54
    }

    // ---- V13 (probe.cc:398-:423): the REAL snort::get_file_proces-
    // sed_size three arms (file_service.cc:254-:270 — the Rust home
    // is the 17q file_flows.rs body over the driver slot; the
    // harness's verbatim-copy witness is RETIRED: the row .o owns the
    // symbol — the landmine); (a) no FileFlows on the slot -> 0;
    // (b) FRESH FileFlows, no current context -> 0 (cc:262-:264);
    // (c) the REAL context through the cache seam + update_file_size
    // (7, SNORT_FILE_MIDDLE) -> 7. The witness positions: the
    // get_file_flows creation -> the NetPol pair (55-56); the
    // get_file_context CACHE-MISS FILE_DEBUG curbkt -> DE (57); the
    // new FileContext -> acquire (58); the creating-new FILE_DEBUG
    // curbkt -> DE (59); update_file_size's curbkt -> DE (60); the
    // dtor's ppc drain -> release (62). Drain VERBATIM fflows. ----
    {
        let mut v13_cache = FileCache::new(16); // `static FileCache v13_cache(16)`
        v13_cache.imgr = imgr.clone(); // the get_file_context seam's manager
        let v13_cache = Rc::new(RefCell::new(v13_cache));
        let mut slot: Option<Rc<RefCell<FileFlows>>> = None; // fcache_clear_flow_slot()
        let flow = CacheFlow::default(); // the harness g_flow (the key seam rides the fixture default)
        let a = get_file_processed_size(slot.as_ref()); // (a) null file_flows
        wit_set_file_service(&mut env, true); // fcache_set_file_service(1) -> the creation switch
        env.svc.set_file_cache(Some(v13_cache.clone())); // fcache_set_file_cache(&v13_cache)
        let ff = FileFlows::get_file_flows(&mut slot, &flow, true, &mut env)
            .expect("the svc-on creation arm"); // -> NetPol pair (lines 55-56)
        let b = get_file_processed_size(slot.as_ref()); // (b) no current context -> 0
        let mut counts = FileCounts::default();
        let mut isnew = false;
        let x = ff
            .borrow_mut()
            // ff->get_file_context(900, true, isnew): the cache-MISS arm ->
            // curbkt DE (57), new FileContext -> acquire (58), the create
            // FILE_DEBUG curbkt -> DE (59).
            .get_file_context(900, true, &mut isnew, 0, &mut env, &mut counts)
            .expect("the create arm");
        ff.borrow_mut().set_current_file_context(&x); // no deferred victim -> silent
        x.borrow_mut().update_file_size(7, SNORT_FILE_MIDDLE, &mut env); // the REAL body -> curbkt DE (60)
        let c = get_file_processed_size(slot.as_ref()); // (c) 7
        push(
            &out,
            format!(
                "V13_size noff={} noctx={} sized={}",
                u8::from(a == 0),
                u8::from(b == 0),
                c
            ),
        ); // line 61
        // The C `set_current_file_context(nullptr)` arm prints nothing
        // (current only — no deferred victim to retire); Rust reaches
        // the same silence via the dtor path below.
        drop(slot); // `ff->set_current...; delete ff; fcache_clear_flow_slot()`: FileFlows Drop -> dtor -> ppc drain -> owner_delete -> the release lands (line 62)
        env.svc.set_file_cache(None); // fcache_set_file_cache(nullptr) (the empty v13_cache drops silent, block end)
        wit_set_file_service(&mut env, false); // fcache_set_file_service(0)
    } // `ff`/`v13_cache`/`x` drop here: the FileFlows dtor fires the IMGR release (line 62)

    // ---- V14 (probe.cc:425-:431): the REAL init() (cc:61-:64):
    // FileFlows::init() INLINED -> the resident create_flow_data_id
    // counter arm: the ladder lands 1 (ffd == flow_data_id == 1). ----
    {
        FileServiceLite::init(&mut env);
        push(
            &out,
            format!("V14_init ffd={}", env.file_flow_data_id.get()),
        ); // line 63
    }

    push(&out, "FSVC_PROBE_DONE"); // line 64

    // ---- per-index assert against the 64-line oracle ----
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
}
