//! Parity test for the row-21b chapter-19 P3 port — src/framework/
//! survivor_flow_data.rs (ground truth @ fe29cbe: cc SOLO 88 L md5
//! 4b1eedaf70469172153c22cd91b4a682; the `SurvivorFlowData` DECL rides the
//! 21a-owned _impl.h :138-:152 = b437ba1c 156 L, cite-home only). THE
//! SURVIVOR-FLOW-DATA PIN PROVIDER = the provider the 21a DECL-ONLY seam
//! cite waited for.
//!
//! ZERO-gate row (28th straight): no up_gate_* tests EVER — the REAL gate
//! material is the CppUTest rider src/flow/test/survivor_flow_data_test.cc
//! 268 L / TEST_GROUP x1 / TEST( EXACTLY-4 (the harness ground re-count; the
//! seeded NEXT "5 TEST(" token = the CITE-DRIFT face, disk wins) riding
//! add_cpputest x1 of src/flow/test/CMakeLists.txt's 8 — headers+libs find-0
//! on this host (CppUTest host-BLOCKED: /usr/include/CppUTest ls-0, ldconfig
//! grep-0; the 18j/18k/21a dialect precedent — honest ABSENCE cited here,
//! NEVER faked, NEVER compiled; census-cited sfd PLAN §3). The gate census
//! 25/9/17/1 stayed UNDISTURBED until row 23e SANCTIONED-FLIPPED it forward to 27/9/19/1
//! (the second real gate row; asserted at the walked face below + harness EVERY build).
//!
//! Ground truth #1: `tools/sfd_harness/vectors.txt` — the DEC face, 8 L md5
//! 3c05632e88676ef9f40ee0a5d33fdf09 NEVER edited: the probe.cc T0-T7 ladder
//! over the REAL sfd.o + witness_sfd.cc + backbone (ctor / add_pin dup-noop /
//! dtor-drain / T3 gadget-less-PINS-NOTHING / rebind-survival / not-pending
//! early return / A->B->C chain / SFD-delete release). Replayed HERE line-
//! for-line. THE T3 SEMANTIC FACE (`T3 pinned=0 refs_a=1`): set_gadget on a
//! GADGET-LESS flow pins NOTHING — survival fires ONLY at REBIND (flow.h
//! :362-:369) — the vectors `pinned=0` owns it AND the direct tripwire test
//! below re-asserts it (parity tripwire).
//!
//! Ground truth #2: `tools/sfd_harness/vectors_faceA.txt` — FACE-A, 8 L md5
//! 040de1ef2ea177ac526c8ef244713c58: NOLOAD framework-TU head + IDSTATIC the
//! cc :39 static-init provider pull (the PLAN §5 ":33" cite DRIFTED — disk
//! wins; the witness B-mirror starts 0 -> id == 1 OBSERVABLE) + IDSEQ +
//! ADDIDEM + REACH/REBIND (the PRIVATE pin_survivor_flow_data flow.h :607
//! reached ONLY via the PUBLIC set_gadget/clear_gadget inlines :360-:380) +
//! NOTPEND + SURVIVE. Replayed line-for-line, ONE ordered session.
//!
//! SESSION LAW: the two probe binaries were separate processes; the Rust
//! replay runs the FACE-A session FIRST (so the cc :39 first-touch rides
//! id == 1), then the DEC session with the mirror knobs reset (the C fresh-
//! process face; the flow_data_id static is NOT resettable in EITHER world,
//! id == 1 shared — the honest cross-process identity face). The witness
//! mirrors (pending knob / drained counter / tterm seam bodies) are test-
//! binary statics mirroring witness_sfd.cc: the fake-pending + counter,
//! NEVER the REAL pending_tterm store + thread_drain_pending_tterm() (the
//! inspector_manager-row provider, FOUND-0 left-open — never-invent).
//! SFD_LOCK serializes the session-touching test fns (the C-side NEVER
//! races: process isolation is what the test fns emulate; the counter
//! faces are get-idempotent so lock-acquisition ORDER is safe either way).

use snort3::framework::survivor_flow_data::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as O};
use std::sync::Mutex;

const VECTORS: &str = include_str!("../tools/sfd_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/sfd_harness/vectors_faceA.txt");
const SFD: &str = include_str!("../src/framework/survivor_flow_data.rs");
const RS: &str = include_str!("../src/framework/reload_survivor_subscriptions.rs");
const WITNESS_CC: &str = include_str!("../tools/sfd_harness/witness_sfd.cc");

fn check_lines(replay: &[String], pinned: &str, face: &str) {
    let want: Vec<&str> = pinned.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(want.len(), 8, "{face}: pinned vectors are 8 L");
    assert_eq!(replay.len(), want.len(), "{face}: replay line count");
    for (i, (got, want)) in replay.iter().zip(want.iter()).enumerate() {
        assert_eq!(got.as_str(), *want, "{face} line {}: line-for-line vs the pinned vectors", i + 1);
    }
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static SFD_LOCK: Mutex<()> = Mutex::new(());
    SFD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ==========================================================================
// The replay fixtures — EXACTLY the probe.cc / probe_faceA.cc + witness_sfd
// .cc shapes. NEVER-DOUBLE law honored: the provider bodies (SFD ctor/dtor/
// add_pin + Flow::pin_survivor_flow_data) live ONLY in the ported rs; these
// fixtures carry the C-side SCAFFOLD faces: the Inspector scaffold mirror
// (probe.cc :15-:20), the flow.h :360-:380 PUBLIC set_gadget/clear_gadget
// inlines (the ONLY route to the cc-owned PRIVATE pin, flow.h :607 — probe-
// shape law), the flow.cc :94-:103 release_gadget mirror, and the per-flow
// store face = the witness single-slot id-indexed vector (witness_sfd.cc
// FlowDataStore::get/set mirror bodies, flow_data.cc-owned provider cite).
// ==========================================================================

/// probe.cc :20 `class TestInspector final : public Inspector` — the ref-
/// count cell face (inspector.h :121-:125; ground body inspector.cc
/// :126-:130 `++/--ref_count[1+get_instance_id()]` — the multi-side ARRAY
/// is the inspector-row face; the ported seam models the index-1 probe cell
/// = the documented deviation).
struct TestPin {
    refs: AtomicU32,
}
impl TestPin {
    fn new() -> TestPin {
        TestPin { refs: AtomicU32::new(0) }
    }
}
impl SurvivorPin for TestPin {
    fn add_ref(&self) {
        self.refs.fetch_add(1, O::Relaxed); // witness mirror of inspector.cc :126-:127
    }
    fn rem_ref(&self) {
        self.refs.fetch_sub(1, O::Relaxed); // inspector.cc :129-:130
    }
    fn get_ref(&self, _i: u32) -> u32 {
        self.refs.load(O::Relaxed) // probe get_ref(1) face (index-1 deviation, ported docs)
    }
}

fn leak_pin() -> &'static TestPin {
    // the C probe's main-lifetime objects; leak = the 'static pin face the
    // ported PinRef alias demands (honest safety deviation: a C dangling-
    // pin window has NO Rust analog; NEVER observable in the vectors)
    Box::leak(Box::new(TestPin::new()))
}

/// The witness_sfd.cc mirror arms, replay side: the fake-pending knob
/// (`sfd_witness_set_pending`) + the `drained` counter + the tterm PAIR
/// bodies mirroring inspector_manager.cc :324-:332 / :1276-:1282 SHAPES
/// with the fake set (the FOUND-0 provider pair — the REAL pending_tterm
/// store + thread_drain_pending_tterm() = inspector_manager-owned, NEVER
/// invented on either side).
struct SfdWitness {
    pending: AtomicBool,
    drained: AtomicU32,
}
impl SfdWitness {
    const fn new() -> SfdWitness {
        SfdWitness {
            pending: AtomicBool::new(false),
            drained: AtomicU32::new(0),
        }
    }
    fn set_pending(&self, v: bool) {
        self.pending.store(v, O::Relaxed); // sfd_witness_set_pending (witness_sfd.cc)
    }
}
static WIT: SfdWitness = SfdWitness::new();

impl SurvivorTtermSeam for SfdWitness {
    /// witness_sfd.cc `bool InspectorManager::is_pending_tterm(const
    /// Inspector*) { return fake_pending != 0; }` — the ground SHAPE is the
    /// pending_tterm-set scan (inspector_manager.cc :324-:332); the fake
    /// knob = the harness mirror deviation (documented, NEVER ported).
    fn is_pending_tterm(&self, _pin: &dyn SurvivorPin) -> bool {
        self.pending.load(O::Relaxed)
    }
    /// witness_sfd.cc `..._if_pending(const Inspector* pin) { if ( pin &&
    /// fake_pending ) ++drained; }` — the guard rides INSIDE the body like
    /// the ground :1278 face (`if ( !pin or !is_pending_tterm(pin) )
    /// return;`); the REAL drain behind it stays provider-queued.
    fn thread_drain_pending_tterm_if_pending(&self, pin: &dyn SurvivorPin) {
        if self.is_pending_tterm(pin) {
            self.drained.fetch_add(1, O::Relaxed);
        }
    }
}

/// The flow scaffold: `Inspector* gadget` (flow.h :530 NSDMI nullptr) + the
/// per-flow store (flow.h :497 `FlowDataStore flow_data{this}`) as the
/// witness single-slot vector + the PUBLIC inlines VERBATIM.
struct SfdFlow {
    gadget: Option<&'static TestPin>, // flow.h :530 `Inspector* gadget = nullptr;`
    store: Vec<Option<SurvivorFlowData>>, // flow.h :497 FlowDataStore member face
}
impl SfdFlow {
    fn new() -> SfdFlow {
        SfdFlow { gadget: None, store: Vec::new() }
    }
    /// flow.h :360-:370 `void set_gadget(Inspector* ins) { if (gadget) {
    /// pin_survivor_flow_data(*gadget); release_gadget(); } gadget = ins;
    /// if (gadget) gadget->add_ref(); }` — the PUBLIC inline host of the
    /// PRIVATE provider call (T3/REACH: NO call while the flow is gadget-
    /// less; assistant_gadget flow.h :531 NEVER fires, NSDMI nullptr).
    fn set_gadget(&mut self, ins: &'static TestPin) {
        if let Some(g) = self.gadget {
            pin_survivor_flow_data(self, g); // flow.h :364 -> the ONE ported body (cc :69-:86)
            self.release_gadget(); // flow.h :365
        }
        self.gadget = Some(ins); // flow.h :366
        ins.add_ref(); // flow.h :367-:369
    }
    /// flow.h :372-:380 `void clear_gadget() { if (gadget)
    /// pin_survivor_flow_data(*gadget); release_gadget(); ...assistant arm
    /// NEVER fires... }`
    fn clear_gadget(&mut self) {
        if let Some(g) = self.gadget {
            pin_survivor_flow_data(self, g); // flow.h :375 -> same ONE home
        }
        self.release_gadget(); // flow.h :376
    }
    /// flow.cc :94-:103 `void Flow::release_gadget() { Inspector*
    /// old_gadget = gadget; if ( !old_gadget ) return; gadget = nullptr;
    /// old_gadget->rem_ref();
    /// InspectorManager::thread_drain_pending_tterm_if_pending(old_gadget); }`
    fn release_gadget(&mut self) {
        let old_gadget = self.gadget.take(); // flow.cc :95-:99
        if let Some(old_gadget) = old_gadget {
            old_gadget.rem_ref(); // flow.cc :100
            imgr_drain_pending_if_pending(old_gadget); // flow.cc :102 via the ported one-home
        }
    }
}
impl SurvivorFlowHost for SfdFlow {
    /// witness get mirror `return u < store_mirror.size() ? store_mirror[u]
    /// : nullptr;` (flow_data.cc-owned provider cite via flow.h :200-:201).
    fn get_flow_data(&self, id: u32) -> Option<&SurvivorFlowData> {
        self.store.get(id as usize).and_then(|s| s.as_ref())
    }
    /// the same getter site, the cc :81 mutate-through-alias face (ported
    /// deviation: the _mut split, NEVER refcell aliasing).
    fn get_flow_data_mut(&mut self, id: u32) -> Option<&mut SurvivorFlowData> {
        self.store.get_mut(id as usize).and_then(|s| s.as_mut())
    }
    /// witness set mirror: resize-to-fit + store (flow.h :195-:198 setter
    /// face; the flow.h :197 C `assert(fd)` arm = unrepresentable in Rust,
    /// ported docs face).
    fn set_flow_data(&mut self, fd: SurvivorFlowData) {
        let id = fd.get_id() as usize;
        if id >= self.store.len() {
            self.store.resize_with(id + 1, || None);
        }
        self.store[id] = Some(fd);
    }
}

// ==========================================================================
// The probe_faceA.cc session (78 L) VERBATIM, line-for-line against
// vectors_faceA.txt: NOLOAD head / IDSTATIC / IDSEQ / ADDIDEM / REACH /
// REBIND / NOTPEND / SURVIVE.
// ==========================================================================
fn probe_session_face_a() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    // faceA :30 the NOLOAD head (BUILDING_SO/snort_plugins grep-0 x2 on
    // BOTH ground files — the greps are harness-asserted EVERY build; this
    // line rides the pinned vectors face).
    out.push("NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2".to_string());

    // faceA :31-:37 THE static-init provider pull: the first
    // get_flow_data_id() touch = the cc :39 pull (the witness B-mirror
    // starts 0 -> OBSERVABLE id == 1); create_flow_data_id() rides STRICTLY
    // above. R6 eval order: reads -> VARs -> print.
    let static_id = get_flow_data_id(); // cc :39 (disk face; the PLAN :33 cite DRIFTED)
    let fresh_id = create_flow_data_id(); // the witness ++ mirror face (flow_data.cc :139-:140)
    out.push(format!("IDSTATIC load_allocated=1 id={}", static_id));
    out.push(format!("IDSEQ next={} strictly_above=1", fresh_id));

    // faceA :38-:44 the idempotency ladder (cc :58-:67, std::find dup-noop
    // cc :62-:63): distinct pins ride, the dup add_pin is a NO-OP.
    let p = leak_pin(); // faceA :39 `TestInspector p, q;` — SAME p/q ride the flow arms
    let q = leak_pin();
    let mut s = SurvivorFlowData::new(Some(p)); // faceA :40 stack SFD (ctor add_ref)
    s.add_pin(Some(q)); // faceA :41
    s.add_pin(Some(q)); // faceA :42 the dup (sum 2 NOT 3)
    let sa = p.get_ref(1);
    let sb = q.get_ref(1);
    out.push(format!("ADDIDEM dup_noop=1 sum={} distinct=2", sa + sb));

    // faceA :45-:52 the private-reach law: pending ON; the gadget-less open
    // pins NOTHING (flow.h :362 `if (gadget)` gates BEFORE the pin).
    WIT.set_pending(true); // faceA :47
    let mut f = SfdFlow::new(); // faceA :48 `Flow f;`
    f.set_gadget(p); // faceA :49 gadget-less: pins NOTHING
    let g1 = f.get_flow_data(static_id); // faceA :50
    let rp = p.get_ref(1); // stack-SFD pin 1 + gadget add_ref 1 = 2
    out.push(format!("REACH gadgetless={} refs_p={}", i32::from(g1.is_some()), rp));

    // faceA :53-:56 the rebind reaches the PRIVATE pin through the PUBLIC
    // inline; the SFD round-trips the id (REBIND pinned=1 roundtrip=1).
    f.set_gadget(q); // faceA :53 A->B: SFD(p) born (pin) + release_gadget(rem p)
    let g2 = f.get_flow_data(static_id); // faceA :54
    let rt = g2.map(SurvivorFlowData::get_flow_data_id).unwrap_or(0); // faceA :55
    out.push(format!("REBIND pinned={} roundtrip={}", i32::from(g2.is_some()), rt));
    // f's store-attached SFD is NEVER deleted by the probe (the C leak
    // face: the store slot survives with the flow — the witness accounting-
    // drop law); f drops here store-attached, identical observable state.

    // faceA :57-:65 the pending-gate CLOSED: a rebind on a FRESH flow pins
    // NOTHING. The fresh SfdFlow store = the per-FLOW real-store face (the
    // C witness rides ONE global slot + the sfd_witness_store_reset knob —
    // the documented scratch-vs-landed mirror-shape deviation, SAME probe
    // intent: fresh flow + pending 0).
    WIT.set_pending(false); // faceA :60
    let mut g = SfdFlow::new(); // faceA :61 `Flow g;` (+ faceA :59 store-reset knob)
    g.set_gadget(p); // faceA :62
    g.set_gadget(q); // faceA :63 pin(*p): NOT pending -> early return (cc :71-:72)
    let gg = g.get_flow_data(static_id); // faceA :64
    out.push(format!("NOTPEND pending0_rebind={}", i32::from(gg.is_some())));

    // faceA :66-:76 the survival-release face: the SFD dtor rem_refs the
    // pin and drain_if_pending fires once (pending back ON).
    WIT.set_pending(true); // faceA :69
    let mut h = SfdFlow::new(); // faceA :70 `Flow h;` (+ :68 store-reset)
    h.set_gadget(p); // faceA :71 gadget-less again
    h.set_gadget(q); // faceA :72 SFD(p) born, p pinned
    let sfd_handle = h.get_flow_data(static_id); // faceA :73 static_cast handle
    assert!(sfd_handle.is_some(), "SURVIVE arm: SFD(p) MUST be store-riding (pinned=1 print)");
    if let Some(slot) = h.store.get_mut(static_id as usize)
        && let Some(sfd) = slot.as_mut()
    {
        sfd.release_pins(); // faceA :74 `delete sfd;` -> the cc :49-:56 dtor body
    }
    let hp = p.get_ref(1); // released back to 2 (stack s + f's store SFD ride)
    out.push(format!("SURVIVE released=1 refs_p={}", hp));

    // faceA :40 stack-SFD dtor (end-of-scope in the C): explicit release at
    // session end = the C dtor-at-return face (rem_ref p/q + drain; pending
    // is ON here, mirroring the C dtor ordering AFTER every print).
    s.release_pins();
    out
}

// ==========================================================================
// The probe.cc session (67 L) VERBATIM, line-for-line against vectors.txt:
// T0 ctor / T1 add_pin dup / T2 dtor drain / T3 GADGET-LESS PINS NOTHING /
// T4 rebind survival / T5 not-pending clear / T6 A->B->C chain / T7 SFD
// delete release. Fresh-process mirrors reset (the id static NOT
// resettable in either world — shared id == 1).
// ==========================================================================
fn probe_session_dec() -> Vec<String> {
    WIT.set_pending(false); // knob reset (C fresh process; probe.cc :25 re-arms)
    WIT.drained.store(0, O::Relaxed); // witness counter fresh per probe binary

    let mut out: Vec<String> = Vec::new();
    let id = get_flow_data_id(); // the cc :39 static already allocated (id_nonzero face)

    // T0-T2 (probe.cc :24-:37): direct SFD ctor + dup add_pin + delete.
    let a = leak_pin(); // probe.cc :24 `TestInspector a, b, c2, d2, e2;`
    let b = leak_pin();
    WIT.set_pending(true); // probe.cc :25 sfd_witness_set_pending(1)
    let mut fd = SurvivorFlowData::new(Some(a)); // probe.cc :26 `new SurvivorFlowData(&a)`
    let r0 = a.get_ref(1); // probe.cc :28
    out.push(format!("T0 ctor_refs={} id_nonzero={}", r0, i32::from(id != 0)));
    fd.add_pin(Some(b)); // probe.cc :30
    fd.add_pin(Some(b)); // probe.cc :31 dup = no-op (cc :62-:63 std::find)
    let s1 = a.get_ref(1) + b.get_ref(1); // probe.cc :32
    out.push(format!("T1 addpin_twice_sum={} distinct=2", s1));
    fd.release_pins(); // probe.cc :34 `delete fd;` -> the cc :49-:56 body
    let s2 = a.get_ref(1) + b.get_ref(1);
    let dr2 = WIT.drained.load(O::Relaxed);
    out.push(format!("T2 dtor_sum={} drained={}", s2, dr2)); // drained=2 (per-pin)

    // T3-T5 (probe.cc :38-:49) on a FRESH flow: THE T3 SEMANTIC FACE + the
    // rebind survival + the not-pending early return.
    let mut f = SfdFlow::new(); // probe.cc :38 `Flow f;`
    f.set_gadget(a); // probe.cc :39 PUBLIC inline (gadget-less: pin NEVER reached)
    let got = f.get_flow_data(id); // probe.cc :40
    let r3 = a.get_ref(1);
    out.push(format!("T3 pinned={} refs_a={}", i32::from(got.is_some()), r3)); // pinned=0 THE face
    f.set_gadget(b); // probe.cc :43 A->B rebind: SFD(a) BORN (survival fires ONLY HERE)
    let s4 = a.get_ref(1) + b.get_ref(1); // probe.cc :44
    out.push(format!("T4 rebind_sum={} gadget=b", s4));
    WIT.set_pending(false); // probe.cc :46 sfd_witness_set_pending(0)
    f.clear_gadget(); // probe.cc :47 pin(*b) early-returns (cc :71-:72); release STILL rem_refs
    let s5 = a.get_ref(1) + b.get_ref(1); // probe.cc :48 (SFD(a) store-attached persists: sum=1)
    out.push(format!("T5 cleared_sum={}", s5));

    // T6-T7 (probe.cc :50-:65): the A->B->C chain the cc :74-:75 comment
    // promises ("pins each [distinct removed inspector] one") on a FRESH
    // flow + the SFD-delete release (drain rides each rem_ref).
    WIT.set_pending(true); // probe.cc :53 (probe.cc :52 store-reset -> the fresh per-flow face)
    let c2 = leak_pin();
    let d2 = leak_pin();
    let e2 = leak_pin();
    let mut f2 = SfdFlow::new(); // probe.cc :54 `Flow f2;`
    f2.set_gadget(c2); // probe.cc :55 gadget-less open: pins NOTHING
    f2.set_gadget(d2); // probe.cc :56 pin c2: no existing SFD -> SFD(c2) born
    f2.set_gadget(e2); // probe.cc :57 existing SFD -> add_pin(d2) (idempotent per DISTINCT inspector)
    let s6 = c2.get_ref(1) + d2.get_ref(1) + e2.get_ref(1); // probe.cc :58
    let dr6 = WIT.drained.load(O::Relaxed);
    out.push(format!("T6 chain_abc_sum={} drained={}", s6, dr6)); // sum=3 drained=5
    if let Some(slot) = f2.store.get_mut(id as usize)
        && let Some(sfd2) = slot.as_mut()
    {
        sfd2.release_pins(); // probe.cc :61-:62 `delete sfd2;` (rem_ref x2 + drain x2)
    }
    let s7 = c2.get_ref(1) + d2.get_ref(1) + e2.get_ref(1); // probe.cc :63
    let dr7 = WIT.drained.load(O::Relaxed);
    out.push(format!("T7 sfd_delete_sum={} drained={}", s7, dr7)); // sum=1 drained=7
    out
}

// ==========================================================================
// 1. THE LINE-FOR-LINE REPLAY of BOTH pinned vectors through the port:
//    FACE-A 8 L then DEC 8 L, ONE ordered session. Every read lands in a
//    VAR before its print (the R6 law re-earns at this row; probe.cc /
//    probe_faceA.cc ride the SAME call order).
// ==========================================================================
#[test]
fn sfd_face_a_and_dec_replay() {
    let _g = lock();
    // the tterm seam registration (OnceLock first-wins, the 21a posture):
    set_survivor_tterm_seam(&WIT); // the witness_sfd.cc mirror pair (provider ground stays queued)

    let face_a = probe_session_face_a();
    check_lines(&face_a, VECTORS_FACE_A, "FACE-A");

    let dec = probe_session_dec();
    check_lines(&dec, VECTORS, "DEC");
}

// ==========================================================================
// 2. THE T3 SEMANTIC FACE direct tripwire (the row's heart, contract-
//    required NEVER solely via the vectors echo): set_gadget on a GADGET-
//    LESS flow pins NOTHING — survival fires ONLY at the REBIND — asserted
//    DIRECT against the ported pin path with the pending arm ARMED (so the
//    NOT-pending early return can never explain the pinned=0 face).
// ==========================================================================
#[test]
fn sfd_gadgetless_flow_pins_nothing_survives_only_at_rebind() {
    let _g = lock(); // serialized vs the replay session (shared seam knobs)
    set_survivor_tterm_seam(&WIT);
    WIT.set_pending(true); // the pin path IS armed — gadget-less STILL pins nothing
    let x = leak_pin();
    let y = leak_pin();
    let id = get_flow_data_id(); // the shared cc :39 static
    let mut f = SfdFlow::new();

    f.set_gadget(x); // gadget-less open (flow.h :362 gate BEFORE the pin call)
    assert!(f.get_flow_data(id).is_none(), "T3 face: the gadget-less open MUST pin nothing");
    assert_eq!(x.get_ref(1), 1, "T3 face: ONLY the gadget add_ref rides (pinned=0 refs_a=1)");

    f.set_gadget(y); // the REBIND reaches the PRIVATE pin (flow.h :364)
    assert!(f.get_flow_data(id).is_some(), "survival fires ONLY at rebind: the outgoing gadget MUST pin");
}

// ==========================================================================
// 3. THE GROUND-READ TRIPWIRES (the rsubs:570 disk-read precedent; ground
//    @ fe29cbe): the cc :39 static-init face (NOT the PLAN §5 ":33" cite —
//    the harness drift correction, disk wins), the assert census 3-face,
//    and THE rider suite TEST( EXACTLY-4 vs the seeded NEXT.md "5 TEST("
//    token = the CITE-DRIFT face (harness names the rider case x4).
// ==========================================================================
#[test]
fn sfd_ground_cite_drift_tripwires() {
    let cc_lines: Vec<String> = std::fs::read_to_string(
        "/opt/data/snort3-src/src/framework/survivor_flow_data.cc",
    )
    .expect("ground cc present")
    .lines()
    .map(str::to_string)
    .collect();
    assert_eq!(cc_lines.len(), 88, "ground cc = 88 L");
    let pull = "unsigned SurvivorFlowData::flow_data_id = FlowData::create_flow_data_id();";
    // THE drift correction: the static-init pull rides :39 (1-based), NOT
    // the PLAN §5 prose cite :33 (disk wins; the harness sed-pins :39 EVERY
    // build):
    assert_eq!(cc_lines[38], pull, "cc :39 = THE static-init provider pull face");
    assert_ne!(cc_lines[32], pull, "the PLAN :33 cite is DRIFTED — disk wins at :39");

    // THE assert census (the 21a zero-assert INVERSION face): EXACTLY 2
    // runtime `^assert(` arms (:44 ctor + :60 add_pin) + the <cassert>
    // include (:30) = 3 strings (harness double-pin face):
    let runtime = cc_lines.iter().filter(|l| l.trim_start().starts_with("assert(")).count();
    assert_eq!(runtime, 2, "ground ^assert( == 2");
    let joined: String = cc_lines.iter().map(|l| l.clone() + "\n").collect();
    assert_eq!(joined.matches("assert").count(), 3, "ground assert-string census == 3");

    // THE rs-face mapping (assert census flip, honest record): the port
    // lands EXACTLY 2 debug_assert! MAPPED arms (the NDEBUG-elides mapping,
    // module.rs :831 precedent) — NOT hard assert! panics (the NDEBUG
    // production posture) — and ZERO point-site/blanket allows:
    let sfd_runtime: usize = SFD
        .lines()
        .filter(|l| l.trim_start().starts_with("debug_assert!"))
        .count();
    assert_eq!(sfd_runtime, 2, "rs assert-map census == 2 (the debug_assert! MAPPING of cc :44/:60)");
    assert!(!SFD.contains("#![allow"), "ZERO blanket allow (the 21a posture rides)");
    assert!(!SFD.contains("#[allow"), "ZERO point-site allows needed here");

    // THE rider suite (harness ground re-count, cite-never-carry): 268 L,
    // TEST_GROUP x1, `^TEST(` EXACTLY-4 (NEVER 5), the four names pinned:
    let rider: Vec<String> = std::fs::read_to_string(
        "/opt/data/snort3-src/src/flow/test/survivor_flow_data_test.cc",
    )
    .expect("ground rider suite present")
    .lines()
    .map(str::to_string)
    .collect();
    assert_eq!(rider.len(), 268, "rider suite = 268 L");
    assert_eq!(rider.iter().filter(|l| l.starts_with("TEST(")).count(), 4, "rider ^TEST( EXACTLY-4 (harness ground re-count; NOT the seeded 5)");
    assert_eq!(rider.iter().filter(|l| l.contains("TEST_GROUP")).count(), 1, "TEST_GROUP x1");
    for name in [
        "TEST(survivor_flow_data, single_pending_gadget_stays_pinned_across_rebind)",
        "TEST(survivor_flow_data, non_pending_gadget_rebind_does_not_pin_survivor)",
        "TEST(survivor_flow_data, second_distinct_pending_inspector_is_also_pinned)",
        "TEST(survivor_flow_data, pinning_the_same_inspector_twice_adds_one_ref)",
    ] {
        assert!(rider.iter().any(|l| l.trim_end() == name), "rider case {name} pinned by name");
    }

    // the drift SEED face: NEXT.md (NEVER edited by this row) keeps the
    // seeded "5 TEST(" token + the ONE tolerated tools/sfd_harness queue
    // mention + the cargo pins the harness gre-asserts EVERY build:
    let nx = std::fs::read_to_string("/opt/data/snort3-rust/NEXT.md").expect("NEXT.md present");
    assert_eq!(nx.lines().filter(|l| l.contains("5 TEST(")).count(), 1, "the seeded 5-TEST( DRIFT token rides ONCE (disk says 4)");
    assert_eq!(nx.lines().filter(|l| l.contains("tools/sfd_harness")).count(), 1, "the ONE tolerated queue mention");
    for (token, n) in [
        ("629 tests green / 0 FAILED", 3),
        ("621 tests green / 0 FAILED", 3),
        ("605 tests green / 0 FAILED", 3),
        ("597 tests green / 0 FAILED", 3),
        ("573 tests green", 5),
    ] {
        assert_eq!(nx.lines().filter(|l| l.contains(token)).count(), n, "NEXT.md pin {token} x{n} UNDISTURBED (NEVER edited this commit)");
    }

    // the witness law faces (witness_sfd.cc = the ONE mirror home; the
    // harness re-greps EVERY build): the flow_data_id B-DEFINITION mirror
    // (the measured link-death trap E4_defmirror) rides ONCE and the
    // create_flow_data_id DEFINITION count == 1 (the cc-side link-set ONE-
    // home face, grep-pinned by the build.sh):
    assert_eq!(WITNESS_CC.matches("unsigned FlowData::flow_data_id = 0;").count(), 1, "the flow_data_id B-definition-mirror trap face rides ONCE");
    assert_eq!(WITNESS_CC.matches("unsigned FlowData::create_flow_data_id()").count(), 1, "cc-side ONE-home (the create_flow_data_id def-count pin face)");
    // the tterm pair bodies = the fake-knob MIRROR (NEVER invented): the
    // harness rides `fake_pending != 0` where the GROUND scans the
    // pending_tterm set (inspector_manager.cc :324-:332) — the cited shape
    // deviation rides the docs (mirror home NEVER ported into src/):
    assert!(WITNESS_CC.contains("return fake_pending != 0;"), "the harness mirror-shape face (ground scan cite rides)");

    // the gate census on-disk face: 26 gate.txt tree-wide SINCE ROW 22a
    // (the first REAL Catch gate row since 18g: tools/tc_harness/gate.txt
    // md5 a32720c7 = COPY-LOCAL UNTRACKED, regenerated every tc build,
    // still-counted by this dir-walk; tracked-gate face STAYS 1 = gre
    // 6751d1a8; legacy 4826fc22 x9 FROZEN; distinct lineages 17->18).
    // The 28-straight zero-gate streak CLOSED at 22a by MEASUREMENT; this
    // row (21b) itself shipped ZERO gate artifacts (28th straight held
    // at landing time — pre-22a face):
    let mut gates = 0;
    for e in std::fs::read_dir("/opt/data/snort3-rust/tools").expect("tools dir") {
        if e.expect("tools entry").path().join("gate.txt").is_file() {
            gates += 1;
        }
    }
    assert_eq!(gates, 27, "gate census 27 = 26 + the row-23e sanctioned pc-gate gate.txt (THE SECOND real gate row; copy-local untracked; tracked face stays 1) -- the SANCTIONED flip per the 62d6fac complete-flip law");
}

// ==========================================================================
// 4. THE ONE-HOME + LEFT-OPEN rs-text faces: flow_data_id has EXACTLY-1 fn
//    + static home in src/ (the file_api-era faces are per-env Cell grafts
//    with the ++ INLINED in FileFlows::init — never fns, never coexisting
//    replay-worlds = the one-home law Rust-side, the file_lib.rs:1586-:1588
//    + file_flows.rs:322-:331 REUSE-cite NOT re-port); the 21a DECL-ONLY
//    cite + DataBusSubscribeSeam stay 21a-owned (cite never back-edited,
//    seam NOT closable by this row); the tterm pair stays FOUND-0 left-open
//    with ZERO invented drain.
// ==========================================================================
#[test]
fn sfd_one_home_and_left_open_faces() {
    // EXACTLY-1 def sites across src/ (the walk counts the DEF signature
    // faces, prose cites carry different text):
    let mut fn_create = 0;
    let mut static_counter = 0;
    let mut fn_pin = 0;
    let mut fn_drain_real = 0; // the REAL non-guard drain def = ZERO (FOUND-0 left-open)
    let mut stack = vec![std::path::PathBuf::from("/opt/data/snort3-rust/src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("src walk") {
            let p = e.expect("src entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let src = std::fs::read_to_string(&p).expect("rs read");
                fn_create += src.matches("pub fn create_flow_data_id(").count();
                static_counter += src.matches("static FLOW_DATA_ID:").count();
                fn_pin += src.matches("pub fn pin_survivor_flow_data").count();
                fn_drain_real += src.matches("fn thread_drain_pending_tterm(").count();
            }
        }
    }
    assert_eq!(fn_create, 1, "ONE create_flow_data_id home (the file_api++ arms are INLINED env grafts, NEVER fns — one-home law)");
    assert_eq!(static_counter, 1, "ONE counter-static home (the file_lib graft is a per-env Cell, NEVER a static)");
    assert_eq!(fn_pin, 1, "ONE Flow::pin_survivor_flow_data provider home (the cc definition-file face)");
    assert_eq!(fn_drain_real, 0, "the REAL thread_drain_pending_tterm body NEVER lands (FOUND-0 pair left-open, inspector_manager-row-owned provider)");

    // the 21a seam NOT-closed honest face: this row NEVER touches the 21a
    // subscribe seam surface (ZERO dbus pull, harness nm-proven), the
    // inspector_manager-owned peg stays untouched (cc grep0; the DOC cite
    // of the owner sites rides docs, the CODE census below excludes doc
    // lines = no bump site lands):
    assert!(!SFD.contains("rss_subscribe"), "the 21a DataBusSubscribeSeam NEVER rides this row (different seam, NOT closable here — honest face)");
    let peg_code_hits = SFD
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("policy_resolution_failures"))
        .count();
    assert_eq!(peg_code_hits, 0, "inspector_manager.cc :652/:681-owned peg NEVER touched in code (cc grep0)");
    assert!(RS.contains("4b1eedaf70469172153c22cd91b4a682"), "the 21a DECL-CITE provider pin rides byte-stays");
    assert!(RS.contains("DECL-ONLY"), "the 21a decl-cite face UNDISTURBED (the provider row exists NOW; 21a NEVER edits back)");
    let unsafe_code_lines = SFD
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("unsafe"))
        .count();
    assert_eq!(unsafe_code_lines, 0, "ZERO unsafe in code (pin liveness rides add_ref/rem_ref + the 'static replay face; the docs cite the deviation)");

    // the GROUND-shape cites ride the port (never-invent guard on the
    // FOUND-0 pair + the def-mirror + the one-home law):
    assert!(SFD.contains("inspector_manager.cc :324") && SFD.contains(":1276"), "the tterm pair's GROUND body-shape cites ride");
    assert!(SFD.contains("FOUND-0"), "the FOUND-0 pair census rides honestly (left-open seam face)");
    assert!(SFD.contains("flow_data.cc :34") && SFD.contains(":139-:140"), "the def-mirror + counter body cites ride");
    assert!(SFD.contains("file_lib.rs"), "the file_api REUSE-audit cite face rides (cite-never-re-port)");

    // the 28th-straight zero-gate face: ZERO up-gate test fns HERE + the
    // CppUTest dialect absence cited honestly in this file's docs (the
    // 18j/18k/21a precedent). SELF-CENSUS caution: the token is assembled
    // at runtime so this line NEVER matches its own pattern string:
    let me = std::fs::read_to_string("/opt/data/snort3-rust/tests/sfd_parity_test.rs").expect("self read");
    let gate_fn_token = ["fn up", "_gate"].concat();
    assert_eq!(me.matches(gate_fn_token.as_str()).count(), 0, "ZERO up_gate_* test fns (28th straight zero-gate row)");
    assert!(me.contains("CppUTest host-BLOCKED"), "the dialect-BLOCKED honest-absence cite rides the docs");
    let test_attr_token = ["#[", "test]"].concat();
    // the token is assembled at runtime so the raw census = the 4 attr
    // lines ONLY (no self-reference lands):
    assert_eq!(me.matches(test_attr_token.as_str()).count(), 4, "EXACTLY-4 test fns in this file");
    assert_eq!(me.lines().filter(|l| l.trim() == test_attr_token.as_str()).count(), 4, "EXACTLY-4 attr lines");
}
