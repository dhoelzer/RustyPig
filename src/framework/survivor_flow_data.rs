//! Flat, cite-heavy literal port of `framework/survivor_flow_data.cc`
//! (ground truth @ fe29cbe: cc 88 L md5 `4b1eedaf70469172153c22cd91b4a682`) =
//! THE SURVIVOR-FLOW-DATA PIN PROVIDER, the chapter-19 P3 row 21b. THE
//! SOLO-CC row: NO sibling header — the `SurvivorFlowData` DECL rides
//! the 21a-owned pair header `_impl.h` (:138-:152; 156 L md5
//! `b437ba1cff967338b48b1b354743d64a`, the 21a LANDED header face), which the
//! cc quotes DIRECT at cc :27. The 21a rs carries the DECL-ONLY documentation
//! mirror (its :1358-:1368 block + module docs :45-:52, cites 88 L /
//! 4b1eedaf verbatim): THAT cite face flips from
//! "provider NOT landed" to "provider = this row" — the 21a file is NEVER
//! edited back (the one-home law: the type's Rust home is THIS row, the
//! decl-cite home stays 21a's).
//!
//! THE T3 SEMANTIC FACE (the row's heart, pinned by vectors.txt line 4
//! `T3 pinned=0 refs_a=1`): set_gadget on a GADGET-LESS flow pins NOTHING —
//! `pin_survivor_flow_data` is reached ONLY from a still-set gadget at a
//! REBIND/teardown (flow.h :364/:375 PUBLIC inlines call the PRIVATE
//! :607 member; cc :71-:72 early-returns unless the outgoing Inspector is
//! pending-tterm). Survival fires ONLY at rebind.
//!
//! ASSERT CENSUS (the 21a flip face, honest): the ground cc carries EXACTLY
//! 3 'assert' strings = 2 runtime (` ^assert(pin);` at :44 ctor + :60
//! add_pin) + the <cassert> include (:30) — 21a's zero-runtime-assert census
//! INVERTS here (harness build.sh pins `^[[:space:]]*assert\(` == 2, 'assert'
//! == 3 EVERY build; the production arm is -DNDEBUG: nm +0 __assert_fail,
//! the NO-NDEBUG arm measures the EXACTLY +1 delta face). Rust mapping per
//! the landed cite precedent (module.rs :831 `debug_assert!(infos.is_some())
//! // cc:365 assert(infos)` — the NDEBUG-elides face): the two runtime arms
//! land as EXACTLY 2 `debug_assert!` arms (cargo test profile runs them;
//! release-profile elides = the NDEBUG face); the <cassert> string has NO
//! Rust arm. NEVER flipped to hard assert!() (the 21a NDEBUG posture).
//!
//! ONE-HOME LAW, flow_data_id (MEASURED C-side trap, harness-pinned): the
//! C link carries EXACTLY ONE `FlowData::create_flow_data_id` definition
//! across the row link inputs (witness_sfd.cc; without the `FlowData::
//! flow_data_id = 0` B-definition mirror the link DIES — E4_defmirror
//! re-measured live every build). AUDIT of landed Rust FIRST: the only
//! landed faces of the same C statics are the file_api-era HARNESS grafts —
//! `FileEnvLite.flow_data_id: Cell<u32>` (file_lib.rs :1586-:1588, cite
//! "FlowData::flow_data_id ... stubs.cc:577 `return ++flow_data_id;`") and
//! the `++` arm INLINED inside `FileFlows::init` (file_flows.rs :322-:331).
//! Those are per-env row-scoped mirrors (the fcapi rig family), NOT a fn
//! home — NEVER re-ported, NEVER touched. THIS row lands the ONE framework-
//! side provider home (`create_flow_data_id` below, body verbatim from
//! flow_data.cc :139-:140); the two worlds NEVER coexist in one replay
//! (the sfd C link set carries NONE of the file_api rigs — grep-pin
//! create_flow_data_id defs == 1; the rs-text tripwire pins EXACTLY-1 `fn
//! create_flow_data_id` in src/). If the flow_data.cc row EVER lands its
//! Rust home, THAT home REPLACES this cited def-mirror (cite-never-carry
//! back), never the reverse.
//!
//! REUSE AUDIT (landed Flow/FlowData faces — cite, NEVER re-declare):
//! `CacheFlow` (file_cache.rs :173) is the file packet-cache flow face, a
//! DIFFERENT model (no gadget/store) — NOT reused. `InspectorApi` +
//! `InspectorManagerApi`/`NullInspectorManager` (file_cache.rs :511/:446/:469)
//! model the file inspect acquire/release trio — DIFFERENT arity, NO
//! add_ref/rem_ref/tterm faces, NEVER reused or patched. The whole
//! `flow/` trio (flow.cc 525 / flow_data.cc 161 / flow_stash.cc 215) stays
//! cite-only unlanded rows: this row provides ONLY what the cc DEFINES —
//! the SurvivorFlowData bodies + the Flow::pin_survivor_flow_data provider
//! body (the body lands HERE per lineage: the cc is the definition file,
//! flow.cc holds only the flow-internal inline hosts at flow.h).
//!
//! WITNESS/SEAM FACES (tools/sfd_harness mirror home; cite ALL, provider-
//! queued, NEVER invented here):
//! * `Inspector::add_ref` / `rem_ref` — FOUND-0 (inspector.cc 175 L row
//!   unlanded); ground BODY face `++/--ref_count[1+get_instance_id()]`
//!   (inspector.cc :126-:130), witness precedent fcap stubs.cc:581 family.
//!   Rust: [`SurvivorPin`] (the Inspector subset THIS row reaches — the 21a
//!   `RssSurvivor` posture; pin identity rides the address face, the 21a
//!   survivor_id precedent).
//! * `InspectorManager::is_pending_tterm` + `thread_drain_pending_tterm_if_
//!   pending` — THE FOUND-0 EXACTLY-2 brand-new pair (grep across ALL landed
//!   Rust + every tools/*/witness*.cc = 0; finspect PLAN :166 earmarks them
//!   InspectorManager-row turf). Ground SHAPES cited: inspector_manager.h
//!   :94-:95 static decls; bodies inspector_manager.cc :324-:332 (pending
//!   set scan) + :1276-:1282 (`if ( !pin or !is_pending_tterm(pin) ) return;
//!   thread_drain_pending_tterm();`). The REAL drain (`thread_drain_pending_
//!   tterm()`, the pending_tterm list teardown) = inspector_manager-owned,
//!   LEFT-OPEN, NEVER-invent: this row lands the cited seam shape with a
//!   NOT-pending default (set unset -> is_pending false -> the cc :71-:72
//!   NOTPEND early return is the DEFAULT arm; the NullInspectorManager null-
//!   manager posture). A C-side honest twin note: the harness witness keeps
//!   the pending knob GLOBAL-fake (witness_sfd.cc), NOT the real per-pin
//!   pending_tterm store — a documented mirror deviation, NEVER ported.
//! * `FlowData` base ctor / dtor + the `flow_data_id` static +
//!   `FlowDataStore::get/set` — FOUND-0 (flow_data.cc unlanded); witness
//!   bodies cited above; Rust: the id-field rides [`SurvivorFlowData`]
//!   directly (the C base ctor body `FlowData(unsigned id) : id(u)` is the
//!   witness FACE, NEVER re-ported as a FlowData type — the flow row owns
//!   it); the store get/set lands as the [`SurvivorFlowHost`] seam (the
//!   flow.h :195-:201 inline face, flow.h-owned).
//! * `SurvivorFlowData::flow_data_id` static-init PULL (cc :39 — THE drift
//!   correction: the PLAN §5 sed cite says ":33", DISK says :39, disk wins,
//!   harness sed-pins :39 EVERY build): `unsigned SurvivorFlowData::
//!   flow_data_id = FlowData::create_flow_data_id();` allocates the id AT
//!   LOAD (FACE-A IDSTATIC: the witness B-mirror starts 0 -> id == 1
//!   OBSERVABLE). Rust: a `OnceLock` first-touch arm (the load-order face
//!   has no Rust analog; the OBSERVABLE first-allocated id == 1 rides the
//!   same counter-starts-0 law, flow_data.cc :34).
//! * 21a seam face, honest: the 21a `DataBusSubscribeSeam` is a DIFFERENT
//!   seam and is NOT closable by this row (the sfd C U-set carries ZERO
//!   data_bus/DataBus symbols — harness nm-proved, grep asserts in the
//!   impl.h-side peg `policy_resolution_failures` stays
//!   inspector_manager.cc :652/:681-owned, NEVER touched here (grep0 on the
//!   cc). The 21a pin `nm <the 21a row .o> | grep -c SurvivorFlowData == 0`
//!   STAYS valid, now definer-PROVEN (this row's sfd.o carries the ctor x2
//!   mirror pin, the 21a build.sh :303 mirror).
//!
//! NDEBUG / clock-seam face: UNIT_TEST grep EXACTLY-0 in the cc (21a's 4/1
//! census INVERTS to a zero-pin here) — NO clock seam lands, UT-vs-plain
//! U-sets IDENTICAL (measured). ZERO enums/tables/sids (contrast the 21a
//! peg-table NAME-drift census); NOLOAD framework-TU (BUILDING_SO/snort_plugins grep-0 x2
//! on both ground files, asserted).
//!
//! Wrapping law: the C static is `unsigned` (u32, wraps); the Rust counter
//! rides `u32` + `wrapping_add` (the C unsigned-overflow face, never a
//! debug panic).

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// cc :23-:35 include face (HAVE_CONFIG_H + config.h; DIRECT :27 impl.h quote;
// <algorithm> :29 = the std::find home; <cassert> :30 = the assert strings;
// flow/flow.h :32 + framework/inspector.h :33 + managers/inspector_manager.h
// :34 — the 3 project heads). Rust needs none: the seams below CITE the
// header homes (the include closure is harness-side, PLAN §1).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE FlowData id statics (flow_data.cc-owned homes; the ONE def-mirror
// home of this row per the one-home law above — flow_data.cc :34
// `unsigned FlowData::flow_data_id = 0;` + :139-:140
// `unsigned FlowData::create_flow_data_id() { return ++flow_data_id; }`).
// ---------------------------------------------------------------------------
static FLOW_DATA_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0); // flow_data.cc :34 (the B-definition face; the harness DEFINITION-MIRROR TRAP: without it the C link DIES — E4_defmirror)

/// flow_data.cc :139-:140 EXACT body face `return ++flow_data_id;` — the
/// C is in `class FlowData`; the row-scoped def-mirror rides the module
/// (one-home census: the ONLY `fn create_flow_data_id` in src/ — the
/// file_api-era env Cell grafts are per-row harness faces, NEVER fns,
/// NEVER coexisting; see module docs). Wrapping law: C `unsigned` ++.
pub fn create_flow_data_id() -> u32 {
    FLOW_DATA_ID
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .wrapping_add(1) // ++flow_data_id (pre-increment READ face)
}

// cc :39 (THE static-init provider pull; the :33 PLAN cite DRIFTED — disk
// wins, build.sh sed-pin :39 == "unsigned SurvivorFlowData::flow_data_id =
// FlowData::create_flow_data_id();"):
// `unsigned SurvivorFlowData::flow_data_id = FlowData::create_flow_data_id();`
// Rust deviation (recorded): C static-init order has no Rust analog ->
// OnceLock first-touch; the OBSERVABLE face (first allocated id == 1, the
// FACE-A IDSTATIC line) rides the same counter-starts-at-0 law.
static SFD_FLOW_DATA_ID: OnceLock<u32> = OnceLock::new(); // cc :39

/// impl.h :147 `static unsigned get_flow_data_id() { return flow_data_id; }`
/// — the inline DECL home is the 21a-owned header (cite-never-carry); the
/// provider body rides cc :32-:86 + this static.
pub fn get_flow_data_id() -> u32 {
    *SFD_FLOW_DATA_ID.get_or_init(create_flow_data_id) // cc :39 pull-on-first-touch face
}

// ---------------------------------------------------------------------------
// THE Inspector pin seam (FOUND-0 provider: inspector.cc 175 L row
// UNLANDED). The row reaches ONLY the ref-count face: inspector.h :124
// `void add_ref();` / :125 `void rem_ref();` / :121 `unsigned get_ref(
// unsigned i)`; ground BODIES inspector.cc :126-:130
// `++/--ref_count[1+get_instance_id()]` (the harness mirror face, fcap
// precedent). C identity = raw `Inspector*` (the std::find compare at cc :62
// is POINTER equality); Rust rides the stable address (the 21a survivor_id
// precedent: ptr::from_ref(...).cast::<()>().addr()).
// DEVIATION (honest): the C `unsigned* ref_count` is a per-side ARRAY
// indexed 1+get_instance_id() and the probe arms only read index 1
// (instance 0 side, probe.cc get_ref(1)); the seam models single-cell
// refcounts — the multi-side array is the inspector row's face.
// ---------------------------------------------------------------------------
pub trait SurvivorPin {
    /// inspector.cc :126-:127 `void Inspector::add_ref() { ++ref_count[1+
    /// get_instance_id()]; }` — the provider body lands with the inspector
    /// row; harness mirror witness_sfd.cc NEVER re-invents behavior.
    fn add_ref(&self);
    /// inspector.cc :129-:130 `void Inspector::rem_ref() { --ref_count[1+
    /// get_instance_id()]; }`
    fn rem_ref(&self);
    /// inspector.h :121 `unsigned get_ref(unsigned i)` — the observable the
    /// probe ladder prints (index 1 face, deviation above).
    fn get_ref(&self, i: u32) -> u32;
}

/// cc :62 POINTER-equality key face (the `std::find` compare) — the 21a
/// survivor_id address precedent (`fn survivor_id(s: &dyn RssSurvivor)`).
fn pin_addr(pin: &dyn SurvivorPin) -> usize {
    let p: *const dyn SurvivorPin = std::ptr::from_ref(pin);
    p.cast::<()>().addr()
}

/// The C raw `Inspector*` pin handle face: Rust carries the non-owning
/// reference (SFD NEVER owns a pin — the add_ref/rem_ref protocol IS the
/// C liveness model; pins are 'static in every replay = the probe's
/// main-lifetime TestInspector face; a C dangling-pin window has NO Rust
/// analog = an honest safety deviation, NEVER a vectors face).
type PinRef = &'static dyn SurvivorPin;

// ---------------------------------------------------------------------------
// THE tterm seam (THE FOUND-0 EXACTLY-2 pair — inspector_manager-owned turf,
// cite-only forever UNTIL the inspector_manager.cc row). Shapes:
// inspector_manager.h :95 `static bool is_pending_tterm(const Inspector*);`
// + :94 `static void thread_drain_pending_tterm_if_pending(const
// Inspector*);`; body SHAPES inspector_manager.cc :324-:332 (scan
// *pending_tterm for pin identity else false) + :1276-:1282
// (`if ( !pin or !is_pending_tterm(pin) ) return;
//   thread_drain_pending_tterm();`). NEVER invented: the REAL drain + the
// REAL pending_tterm store land with the inspector_manager row — this seam
// defaults to NOT-pending (unset => is_pending false => the cc :71-:72 early
// return = the honest default arm, the null-manager posture file_cache.rs
// :469). The harness witness's global fake-pending knob (witness_sfd.cc) is
// the mirror deviation, NEVER ported.
// ---------------------------------------------------------------------------
pub trait SurvivorTtermSeam: Send + Sync {
    /// inspector_manager.h :95 / body-shape cite inspector_manager.cc :324.
    fn is_pending_tterm(&self, pin: &dyn SurvivorPin) -> bool;
    /// inspector_manager.h :94 / body-shape cite inspector_manager.cc :1276
    /// — the early-return GUARD face lands verbatim below in
    /// [`imgr_drain_pending_if_pending`]; the drain ITSELF is provider
    /// queued (NEVER invented here).
    fn thread_drain_pending_tterm_if_pending(&self, pin: &dyn SurvivorPin);
}

static IMGR_TTERM_SEAM: OnceLock<&'static dyn SurvivorTtermSeam> = OnceLock::new();

/// Register the tterm seam (idempotent OnceLock first-wins, the 21a
/// set_rss_config_seam posture) — the parity replay registers the harness
/// witness MIRROR; production stays provider-queued (unset = not-pending).
pub fn set_survivor_tterm_seam(seam: &'static dyn SurvivorTtermSeam) {
    let _ = IMGR_TTERM_SEAM.set(seam);
}

/// cc :71 `InspectorManager::is_pending_tterm(&outgoing)` — the unset-seam
/// arm models `!pending_tterm` -> false (inspector_manager.cc :326-:327
/// `if ( !pending_tterm ) return false;`). pub: the flow.cc-row mirror face
/// (release_gadget flow.cc :102) and the test replay reach the ONE home.
pub fn imgr_is_pending_tterm(pin: PinRef) -> bool {
    match IMGR_TTERM_SEAM.get() {
        Some(s) => s.is_pending_tterm(pin),
        None => false,
    }
}

/// cc :54 dtor call site + flow.cc release_gadget :102 face —
/// `InspectorManager::thread_drain_pending_tterm_if_pending(pin)`.
pub fn imgr_drain_pending_if_pending(pin: PinRef) {
    if let Some(s) = IMGR_TTERM_SEAM.get() {
        s.thread_drain_pending_tterm_if_pending(pin);
    }
}

// ---------------------------------------------------------------------------
// THE flow-side host seam: pin_survivor_flow_data is a Flow MEMBER
/// (flow.h :607 PRIVATE `void pin_survivor_flow_data(Inspector&);`) whose
// BODY this row OWNS (cc :69-:86); it reaches ONLY the flow.h :195-:201
// PUBLIC inlines `set_flow_data(FlowData* fd)` (`assert(fd);
// flow_data.set(fd);`) + `get_flow_data(unsigned id) const`
// (`return flow_data.get(id);`) over the per-FLOW `FlowDataStore
// flow_data{this}` member (flow.h :497; flow_data.cc row UNLANDED — the
// harness witness keeps a single-slot id-indexed vector mirror there).
// DEVIATION (honest, one-home law): the C get returns the base pointer and
// the BODY mutates THROUGH it (non-const alias); the Rust seam splits the
// mutate path into `_mut` (same cite site) instead of aliasing &mut out of
// an immutable getter — no RefCell, no unsafe, NEVER a vectors face. The
// flow.h :197 `assert(fd)` arm needs no Rust site (the C null ptr is
// unrepresentable — the Option face covers the getter side).
// ---------------------------------------------------------------------------
pub trait SurvivorFlowHost {
    /// flow.h :200-:201 `FlowData* get_flow_data(unsigned id) const` (the
    /// :76-:77 static_cast<SurvivorFlowData*> site rides the seam typing).
    fn get_flow_data(&self, id: u32) -> Option<&SurvivorFlowData>;
    /// the cc :81 MUTATE-THROUGH-POINTER face (same getter site, C
    /// non-const alias; deviation above).
    fn get_flow_data_mut(&mut self, id: u32) -> Option<&mut SurvivorFlowData>;
    /// flow.h :195-:198 `void set_flow_data(FlowData* fd) { assert(fd);
    /// flow_data.set(fd); }` — the store insert is FlowDataStore-owned
    /// (flow_data.cc, cite-only; harness mirror body witness_sfd.cc).
    fn set_flow_data(&mut self, fd: SurvivorFlowData);
}

// ---------------------------------------------------------------------------
// impl.h :138-:152 `class SurvivorFlowData : public FlowData` — THE provider
// type (the 21a DECL-ONLY cite face COMPLETES here; the 21a rs block is
// NEVER edited back). impl.h :137 "pins a survivor Inspector alive across
// mid-flow gadget rebinds".
// ---------------------------------------------------------------------------

/// impl.h :150 `std::vector<Inspector*> pinned;` (pointer identity);
/// impl.h :151 `static unsigned flow_data_id;` (the cc :39 static —
/// module-level [`SFD_FLOW_DATA_ID`], the C class-static face). The FlowData
/// base id field (flow_data.h :76 `unsigned id`, protected) rides directly
/// — the base ctor BODY is the witness mirror cite face, NEVER a landed
/// FlowData type (the flow row owns it).
pub struct SurvivorFlowData {
    id: u32,                                    // FlowData(flow_data_id) — cc :42 base-init face
    pinned: Vec<PinRef>,                        // impl.h :150
}

impl SurvivorFlowData {
    /// cc :41-:47 `SurvivorFlowData::SurvivorFlowData(Inspector* pin) :
    /// FlowData(flow_data_id) { assert(pin); pinned.push_back(pin);
    /// pin->add_ref(); }` — eval order VAR-first (the R6 law re-earns):
    /// the base id read, the assert, the push, the add_ref.
    pub fn new(pin: Option<PinRef>) -> SurvivorFlowData {
        // cc :42 `: FlowData(flow_data_id)` — the static READ (base-init
        // list runs BEFORE the body in the C).
        let id = get_flow_data_id();
        // cc :44 `assert(pin);` — the NDEBUG-elides face (module.rs :831
        // precedent); the C null-pin arm past NDEBUG is UB, the debug arm
        // trips here (the harness NEVER compiles a null-pin arm: probe.cc
        // has ZERO null sites).
        debug_assert!(pin.is_some(), "cc :44 `assert(pin);` (the ctor null-pin guard)");
        let pin: PinRef = pin.expect("cc :44 assert(pin) arm — harness never reaches it");
        let mut s = SurvivorFlowData { id, pinned: Vec::new() };
        s.pinned.push(pin); // cc :45
        pin.add_ref(); // cc :46
        s
    }

    /// impl.h :142 `~SurvivorFlowData() override;` — the cc :49-:56 BODY
    /// face. DEVIATION (recorded, NEVER-invent): Rust has NO manual
    /// `delete` and NO Drop (a Drop would re-run side effects the probe's
    /// explicit delete sites already drive -> the dtor arm lands EXPLICIT,
    /// mirroring the probe's `delete fd` / `delete sfd2` points); the real
    /// store-retired teardown rides the flow_data.cc row (the witness
    /// accounting-drop law: the store slot SURVIVES a pin-release, the
    /// pins' survival is the row's own semantic).
    pub fn release_pins(&mut self) {
        // cc :51-:55 `for ( auto* pin : pinned ) { pin->rem_ref();
        // InspectorManager::thread_drain_pending_tterm_if_pending(pin); }`
        for pin in self.pinned.iter() {
            pin.rem_ref(); // cc :53
            imgr_drain_pending_if_pending(*pin); // cc :54
        }
    }

    /// impl.h :147 `static unsigned get_flow_data_id() { return
    /// flow_data_id; }` — the member face over the module static.
    pub fn get_flow_data_id(&self) -> u32 {
        get_flow_data_id() // impl.h :147 (the C reads the class static, NOT the instance)
    }

    /// The base id read face (flow_data.h :45-:46 `unsigned get_id() const
    /// { return id; }`) — the store-key compare site; NEVER a re-declared
    /// FlowData type.
    pub fn get_id(&self) -> u32 {
        self.id
    }

    /// impl.h :144 `void add_pin(Inspector* pin);` — "idempotent: adding an
    /// already-held pin is a no-op" (:143). cc :58-:67 verbatim:
    /// assert -> std::find dup check -> push -> add_ref.
    pub fn add_pin(&mut self, pin: Option<PinRef>) {
        debug_assert!(pin.is_some(), "cc :60 `assert(pin);` (the add_pin null-pin guard)");
        let pin: PinRef = pin.expect("cc :60 assert(pin) arm — harness never reaches it");

        // cc :62-:63 `if ( std::find(pinned.begin(), pinned.end(), pin) !=
        // pinned.end() ) return;` — POINTER-equality scan (cc :74-:75
        // "idempotent per distinct inspector -- a flow rebinding through
        // multiple removed inspectors (A -> B -> C) pins each one").
        let addr = pin_addr(pin);
        if self.pinned.iter().any(|p| pin_addr(*p) == addr) {
            return;
        }

        self.pinned.push(pin); // cc :65
        pin.add_ref(); // cc :66
    }
}

// cc :69-:86 `void Flow::pin_survivor_flow_data(Inspector& outgoing)` — THE
// provider body (definition home = THIS cc; flow.h :607 PRIVATE decl,
// reached ONLY from the flow.h :364/:375 set_gadget/clear_gadget PUBLIC
// inlines — a flow.h-owned probe-shape law replayed harness/test-side,
// NEVER landed here: those inlines belong to the flow.cc 525-L row). The
// host seam [`SurvivorFlowHost`] carries the two PUBLIC getter/setter
// faces the body touches.
pub fn pin_survivor_flow_data<H: SurvivorFlowHost + ?Sized>(flow: &mut H, outgoing: PinRef) {
    // cc :71-:72 `if ( !InspectorManager::is_pending_tterm(&outgoing) )
    // return;` — NOT-pending early return (the T3/T5/NOTPEND vectors spine;
    // the unset seam defaults false = the inspector_manager-owned provider
    // posture above).
    if !imgr_is_pending_tterm(outgoing) {
        return;
    }

    // cc :76-:77 `auto* existing = static_cast<SurvivorFlowData*>(
    //     get_flow_data(SurvivorFlowData::get_flow_data_id()));`
    let id = get_flow_data_id();
    if let Some(existing) = flow.get_flow_data_mut(id) {
        // cc :79-:83 `if ( existing ) { existing->add_pin(&outgoing);
        // return; }`
        existing.add_pin(Some(outgoing));
        return;
    }

    // cc :85 `set_flow_data(new SurvivorFlowData(&outgoing));` — the SFD
    // BORN face (survival fires ONLY at rebind, T4/REBIND/SURVIVE pins).
    let fd = SurvivorFlowData::new(Some(outgoing));
    flow.set_flow_data(fd);
}

// ---------------------------------------------------------------------------
// THE store-keying helper the parity replay drives = the harness witness
// single-slot id-indexed store face (witness_sfd.cc FlowDataStore::get/set
// mirror, flow_data.cc-owned provider cite: get = bounds-checked index, set
// = resize-to-fit + store). It lands test-side (the mirror home = the probe/
// witness law: NEVER in port src), so NOTHING beyond the host seam exists
// here for the store.
// ---------------------------------------------------------------------------

