//! Parity port of `src/file_api/file_inspect.{h,cc}` — row 17w: the
//! inspector-registration TU. FileInspect never inspects (inline-empty
//! `eval` h:33 = no body, no symbol, no vector, PLAN R11; IT_PASSIVE
//! cc:161): its whole payload is the wiring ladder — the steal ctor
//! (cc:48-:51), configure() arming the REAL FileCache trio + the
//! pub-id static + the MP-bus subscription (cc:59-:85), the
//! ConfigLogger show ladder (cc:90-:123), the REAL
//! `get_file_adv_pub_id` getter over the cc:46 static (cc:87-:88) and
//! the `sin_file_flow` InspectApi record (cc:147-:175).
//!
//! Ground truth: tools/finspect_harness (probe V1-V8 arms; this TU has
//! ZERO TEST_CASEs/UNIT_TEST fragments — vectors.txt (103 L, md5
//! 3cbd009e9bb4228ee427ed3fadc64fb4) is the only oracle; NEVER edit).
//! Replay: tests/finspect_parity_test.rs (drives THIS module end to
//! end: the real configure()/show()/ctor ladder + the witness impls).
//!
//! h:36 closure (the 17u LEFT-OPEN at file_config.rs:240-:243): the
//! `class FileConfig* config` member lands HERE as
//! `FileInspect::config: Option<Rc<RefCell<FileConfigLite>>>` — the
//! FileConfigLite (full-table) side of the PLAN 3.3 closeability
//! verdict; the 17p `InspectorApi::config -> FileConfigView` trait and
//! the FileContext.config duality stay UNTOUCHED (R7: swapping them
//! re-arms every pinned 17p/17r vector). `FileEnvLite::file_config`
//! keeps serving the frozen fconf G1/G2/G3 seams (fconf vectors
//! line 1 "FileInspect ctor" is the RETIRED stub-witness print — a
//! frozen-oracle position pin, R6; the REAL cc:48 ctor prints NOTHING:
//! only the load_config witness ride, vectors line 1 `FIM load_config`).
//!
//! Seam states consolidated by this row (PLAN 3.1/3.2):
//! * cc:46 `static std::atomic<unsigned> file_adv_pub_id` == the
//!   `FileEnvLite::adv_pub_id: Cell<u32>` slot (the 17q interim home,
//!   canonical here); atomics not reproduced (17v R2 posture). The
//!   REAL getter `get_file_adv_pub_id` lives below and file_lib.rs's
//!   file_lib.cc:658 publish seam is re-pointed to it (pub name
//!   stable); configure()'s cc:74 arm is the only writer.
//! * cc:72 set_max_file_depth reads/writes `env.max_file_depth` (the
//!   g_max_file_depth harness static, 17q) and `env.file_config` (the
//!   REAL get_file_config chain of file_config.cc:89-:100 reading the
//!   h:36 member now, R9 — the Rust seam is that chain's single
//!   resolution).
//! * cc:76 `sc->mp_dbus` == the new `FileEnvLite::mp_dbus` slot (the
//!   fcache_set_mp_dbus harness shim); FileCache::conf.mp_dbus stays
//!   the 17p cache-side view of the SAME C static — two views, same
//!   ruling as the config duality.
//! * The show ladder rides the REAL ported `log::messages::ConfigLogger`
//!   (row 17j: CAPTION "%*s: " indention 25, `log_flag` RETURNS the
//!   flag — real messages.cc:364-:371, overload collapse R4: int64_t
//!   fields -> log_value_int, the uint64_t max_files_per_flow ->
//!   log_value_uint). The harness stand-in prefix every engine line
//!   with "CFGLOG " (vectors posture); the replay reconstructs that.
//!
//! Witness-body posture: DataBus::get_id / MPDataBus::register_event_
//! helpers + subscribe / the INSTRUMENTED set_max_file_depth walk are
//! unported layers (data_bus/mp_data_bus/file_service rows) — the
//! stubs-witness twins below print into a shared collector
//! (`println` in C -> Vec<String> here, the one translation the row
//! makes; the C printf lines are pinned verbatim by vectors.txt).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::file_cache_share::{FileMpEvent, deserialize_file_event, serialize_file_event};
use super::file_config::{FILE_ID_HELP, FILE_ID_NAME};
use super::file_lib::{FileConfigLite, FileEnvLite, FileServiceLite};

// ------------------------------------------------------------------
// pub_sub/file_events_ids.h ids + PubKeys (the pub_sub row is an
// unported layer — row-local consts, 17u const-home recipe; the
// file_adv_pub_key name/events land at the configure() call site):
//   file_mp_pub_key { "file_mp_events", num_ids } (h:49; FILE_SHARE =
//   0 / FILE_SHARE_SYNC = 1 / num_ids = 2, h:30-:36) and
//   file_adv_pub_key { "file_adv_events", num_ids } (h:50;
//   FILE_COMPLETE = 0 / num_ids = 1, h:42-:46 — FILE_COMPLETE itself
//   already lives at file_lib.rs FILE_EVENT_ID_FILE_COMPLETE).
// ------------------------------------------------------------------
pub const FILE_MP_PUB_KEY: &str = "file_mp_events";
pub const FILE_MP_NUM_EVENTS: u32 = 2;
pub const FILE_MP_EVENT_ID_FILE_SHARE: u32 = 0;
pub const FILE_MP_EVENT_ID_FILE_SHARE_SYNC: u32 = 1;
pub const FILE_ADV_PUB_KEY: &str = "file_adv_events";
pub const FILE_ADV_NUM_EVENTS: u32 = 1;

// BaseApi/InspectApi record consts (framework row unported — these
// copy the header enums VERBATIM; the detection/rtn_checks.rs
// PROTO_BIT mirror precedent covers the cross-TU copy). V7_base/V7_api
// read them back off the record.
/// base_api.h:41 `#define BASE_API_VERSION 29`
pub const BASE_API_VERSION: u32 = 29;
/// inspector.h:52 `#define INSAPI_VERSION ((BASE_API_VERSION << 16) | 5)`
/// (V7 renders the hi/lo split: apiver=29 apiver_lo=5)
pub const INSAPI_VERSION: u32 = (BASE_API_VERSION << 16) | 5;
/// base_api.h:47-:61 enum PlugType — PT_INSPECTOR = 1 (V7 `type=1`)
pub const PT_INSPECTOR: u32 = 1;
/// base_api.h:48 `#define API_RESERVED 0` (features-slot value)
pub const API_RESERVED: u64 = 0;
/// the harness-written framework/api_options.h `#define API_OPTIONS 0`
/// (fcapi/finspect build.sh:87; the real tree carries the option bits —
/// the link fact, not a donor fact)
pub const API_OPTIONS: u32 = 0;
/// inspector.h:245-:256 enum InspectorType — IT_PASSIVE = 0 (V7
/// `itype=0`; "config only" — h:33 inline-empty eval, never inspects)
pub const IT_PASSIVE: u32 = 0;
/// framework/decode_data.h PROTO_BIT__NONE (V7 `proto_bits=0`;
/// detection/rtn_checks.rs:24 mirrors the same 0)
pub const PROTO_BIT__NONE: u32 = 0;
/// probe pin `size=152` = sizeof(InspectApi) on the C++ layout — the
/// first sizeof(=112, BaseApi) + InspectApi tail; a vptr-bearing fact
/// no Rust type replicates (PROBE_SIZEOF precedent: pinned, never
/// faked via size_of).
pub const PROBE_SIZEOF_INSPECT_API: usize = 152;

/// The witness-print collector seam: C witness bodies call `printf`
/// (vectors.txt captures stdout); the Rust twins append identical
/// lines to a driver-owned Vec. This is the ONLY shape translation the
/// row makes — every line TEXT stays byte-pinned.
pub type WitnessOut = Rc<RefCell<Vec<String>>>;

pub fn push_witness(out: &WitnessOut, s: impl Into<String>) {
    out.borrow_mut().push(s.into());
}

// ------------------------------------------------------------------
// Witness seams for the unported layers configure() rides.
// ------------------------------------------------------------------

/// `static unsigned DataBus::get_id(const PubKey&)` (data_bus.h:108;
/// REAL body data_bus.cc:98 NOT linked — finspect witness #1). The
/// configure() arm cc:74 writes the returned id into the pub-id static.
pub trait DataBusIdSeam {
    fn get_id(&mut self, publisher: &str, num_events: u32) -> u32;
}

/// Default = the finspect stubs witness #1 verbatim: print + answer
/// the ARMABLE pinned id (7 default = the frozen `PUB pub=7` id family
/// across fcache/fctx/fflows oracles, R6; re-pinning to 9 drives the
/// V4 static round trip `finspect_set_dbus_get_id(9)`).
pub struct EchoDataBusId {
    pub witness_id: Cell<u32>,
    pub out: WitnessOut,
}

impl EchoDataBusId {
    pub fn new(out: &WitnessOut) -> Self {
        EchoDataBusId {
            witness_id: Cell::new(7),
            out: out.clone(),
        }
    }
}

impl DataBusIdSeam for EchoDataBusId {
    fn get_id(&mut self, publisher: &str, num_events: u32) -> u32 {
        let id = self.witness_id.get();
        push_witness(&self.out, format!("DBUS get_id name={publisher} events={num_events} -> {id}"));
        id
    }
}

/// The 17t codec pair cc:78-:79 binds (file_cache_share.rs; the C
/// MPSerializeFunc/MPDeserializeFunc typedefs, mp_data_bus.h) — named
/// so the seam signatures stay readable (clippy type-complexity).
pub type MpSerializeFn = fn(Option<&mut FileMpEvent>) -> Option<(Vec<u8>, u16)>;
pub type MpDeserializeFn = fn(&[u8], u16) -> Option<FileMpEvent>;

/// MPDataBus witnesses #2 + #3 (mp_data_bus.h:173/:155; call sites
/// cc:81/:82). `register_event_helpers` carries the REAL 17t codec
/// pair — C cc:78-:79 binds `serialize_file_event`/
/// `deserialize_file_event` and the witness prints liveness ONLY
/// (ser=1/deser=1, never addresses — R13). `subscribe` carries the
/// DataHandler name the `new FileCacheShare()` binds
/// (file_cache_share.h:32): C hands the allocation to the perpetual
/// bus (file_cache_share.rs:306-:309 "never deletes it") — the Rust
/// seam models the hand-off by NAME and never allocates a subscriber
/// (PLAN: two printed facts, never a real bus).
pub trait MpBusSeam {
    fn register_event_helpers(
        &mut self,
        publisher: &str,
        evt: u32,
        ser: MpSerializeFn,
        deser: MpDeserializeFn,
    );
    fn subscribe(&mut self, publisher: &str, evt: u32, handler_name: &'static str);
}

/// Call-counting default (stubs g_mp_reg_calls/g_mp_sub_calls behind
/// the V5 pins `V5_skip reg=0` / `V5_arm reg=1 sub=1`). A fn-pointer
/// parameter is never null in Rust — the ser/deser liveness print of
/// the C witness is structural here (the bound pair is the real 17t
/// codec, cc:78-:79 binds real symbols -> ser=1/deser=1 always).
pub struct EchoMpBus {
    pub reg_calls: u32,
    pub sub_calls: u32,
    out: WitnessOut,
}

impl EchoMpBus {
    pub fn new(out: &WitnessOut) -> Self {
        EchoMpBus {
            reg_calls: 0,
            sub_calls: 0,
            out: out.clone(),
        }
    }
}

impl MpBusSeam for EchoMpBus {
    fn register_event_helpers(
        &mut self,
        publisher: &str,
        evt: u32,
        _ser: fn(Option<&mut FileMpEvent>) -> Option<(Vec<u8>, u16)>,
        _deser: fn(&[u8], u16) -> Option<FileMpEvent>,
    ) {
        push_witness(
            &self.out,
            format!("MPDBUS reg_helpers name={publisher} evt={evt} ser=1 deser=1"),
        );
        self.reg_calls += 1;
    }
    fn subscribe(&mut self, publisher: &str, evt: u32, handler_name: &'static str) {
        push_witness(
            &self.out,
            format!("MPDBUS sub name={publisher} evt={evt} handler={handler_name}"),
        );
        self.sub_calls += 1;
    }
}

/// `FileService::set_max_file_depth(sc)` (cc:72) — the INSTRUMENTED
/// witness body (NEXT.md:123 "instrument it, don't retire"; stubs.cc
/// NEW17w): the REAL file_service.cc:227-:251 walk (type arm ->
/// signature bump arm -> the extra-byte arm cc:245-:248) over the
/// REAL get_file_config chain plus the g_max_file_depth arm/readout.
/// The conf=0/conf=1 prints + the env.max_file_depth write are harness
/// instrumentation — the real file_service row's body is silent and
/// `get_max_file_depth` (file_service.cc:214) has an `fc` arm
/// (file_config->file_depth > 0 ? : -1); the 17q passthrough ruling
/// on `FileEnvLite::get_max_file_depth` stands.
pub trait SmdSeam {
    fn set_max_file_depth(&mut self, env: &mut FileEnvLite);
}

pub struct EchoSmd {
    out: WitnessOut,
}

impl EchoSmd {
    pub fn new(out: &WitnessOut) -> Self {
        EchoSmd { out: out.clone() }
    }
}

impl SmdSeam for EchoSmd {
    fn set_max_file_depth(&mut self, env: &mut FileEnvLite) {
        match env.get_file_config() {
            // conf-null arm (V3 pin `SMD conf=0 depth=10485761`): the
            // real body returns silently; the readout is witness.
            None => push_witness(
                &self.out,
                format!("SMD conf=0 depth={}", env.max_file_depth.get()),
            ),
            Some(cfg) => {
                {
                    let mut c = cfg.borrow_mut();
                    if env.svc.is_file_type_id_enabled() {
                        c.file_depth = c.file_type_depth; // file_service.cc:233-:236
                    }
                    if env.svc.is_file_signature_enabled()
                        && c.file_signature_depth > c.file_depth
                    {
                        c.file_depth = c.file_signature_depth; // :238-:241
                    }
                    if c.file_depth > 0 {
                        /*Extra byte for deciding whether file data will be over limit*/
                        c.file_depth += 1; // :243-:246
                    }
                    env.max_file_depth.set(c.file_depth); // g_max_file_depth
                    push_witness(&self.out, format!("SMD conf=1 depth={}", c.file_depth));
                }
            }
        }
    }
}

// ------------------------------------------------------------------
// FileInspect (file_inspect.h:28-:37) — the row TU.
// ------------------------------------------------------------------

/// `class FileInspect : public snort::Inspector` (h:28). C `eval`
/// (h:33) is INLINE-EMPTY — no body, no symbol, no eval vector (R11):
/// the Rust type carries no eval method either (IT_PASSIVE, cc:161).
pub struct FileInspect {
    /// h:36 `class FileConfig* config` — the PUBLIC raw-pointer member
    /// as the full-table Rc (the 17u LEFT-OPEN closed on the
    /// FileConfigLite side per PLAN 3.3; the 17p FileConfigView trait
    /// and the FileContext duality untouched, R7).
    pub config: Option<Rc<RefCell<FileConfigLite>>>,
}

impl FileInspect {
    /// cc:48-:51 `FileInspect(FileIdModule* fm) { fm->load_config(config); }`
    /// — the STEAL ctor. `FileIdModule` is an unported row; the real
    /// load_config body (file_module.cc:263-:266) is exactly
    /// `dst = fc; fc = nullptr;` (a plain member fn, NOT virtual,
    /// file_module.h:61), so the Rust parameter IS the module's config
    /// slot and `take()` IS the steal: a second ctor over the same
    /// source lands the null arm -> the cc:61/:121 null arms (probe
    /// V8a `first=1 second=0`). No witness load_config print here:
    /// ctor and dtor print NOTHING (vectors R5/§4 — the retired stub
    /// ctor print lives on only as a frozen fconf line-1 pin).
    pub fn new(mod_config: &mut Option<Rc<RefCell<FileConfigLite>>>) -> Self {
        FileInspect {
            config: mod_config.take(),
        }
    }

    // (not a doc comment on purpose: it describes the intentionally
    // ABSENT Rust method -- there is nothing to attach it to.)
    // cc:53-:57 `~FileInspect() { if (config) delete config; }` —
    // single-owner delete == Rust drop of the sole owning Rc (PLAN
    // R2: the hand-off is heap-only, never static storage; the C
    // dtor is only ever reached through the heap file_dtor, cc:142-
    // :145 — mirrored by the V7 wiring arm file_ctor -> drop).
    // Drop is the whole translation: no explicit body.

    /// cc:59-:85 VERBATIM order: null-config early return (:61-:62) ->
    /// FileService::get_file_cache() + the trio through the REAL 17p
    /// FileCache setters (`file_cache.rs` set_block_timeout/
    /// set_lookup_timeout/set_max_files — the clamp arm with its
    /// ErrorMessage print rides free, file_cache.cc:140-:153) ->
    /// `set_max_file_depth` (:72) -> the pub-id static arm (:74) ->
    /// the `mp_dbus` subscription arm (:76-:83). V1 proves the early
    /// return carries NO witness line, V2/V2_clamp the trio + clamp,
    /// V4 the static round trip, V5 the skip + armed arms.
    pub fn configure(
        &mut self,
        env: &mut FileEnvLite,
        dbus: &mut dyn DataBusIdSeam,
        mp: &mut dyn MpBusSeam,
        smd: &mut dyn SmdSeam,
    ) -> bool {
        // cc:61-:62
        if self.config.is_none() {
            return true;
        }

        // cc:64-:70 (inline getter file_service.h:98 -> env.svc slot;
        // fields read off the h:36 member, cache side via &mut borrows)
        if let Some(cache) = env.svc.get_file_cache() {
            let (bt, lt, mfc) = {
                let c = self.config.as_ref().unwrap().borrow();
                (c.file_block_timeout, c.file_lookup_timeout, c.max_files_cached)
            };
            cache.borrow_mut().set_block_timeout(bt);
            cache.borrow_mut().set_lookup_timeout(lt);
            cache.borrow_mut().set_max_files(mfc);
        }

        // cc:72
        smd.set_max_file_depth(env);

        // cc:74 `file_adv_pub_id = DataBus::get_id(file_adv_pub_key);`
        // -- the C file-local atomic (cc:46) is env.adv_pub_id; the
        // V4 vectors pin the round trip through the real getter below.
        env.adv_pub_id.set(dbus.get_id(FILE_ADV_PUB_KEY, FILE_ADV_NUM_EVENTS));

        // cc:76-:83: sc->mp_dbus -> env.mp_dbus (deviation, header);
        // the codec pair cc:78-:79 is the REAL 17t serialize/
        // deserialize_file_event; the handler name rides the REAL
        // 17t FileCacheShare type's binding.
        if env.mp_dbus.get() {
            mp.register_event_helpers(
                FILE_MP_PUB_KEY,
                FILE_MP_EVENT_ID_FILE_SHARE_SYNC,
                serialize_file_event,
                deserialize_file_event,
            );
            mp.subscribe(
                FILE_MP_PUB_KEY,
                FILE_MP_EVENT_ID_FILE_SHARE_SYNC,
                super::file_cache_share::FileCacheShare::new().name,
            );
        }
        true
    }

    /// cc:119-:123 `void show(const SnortConfig*) const { if (config)
    /// file_config_show(config); }` — the null-guard arm (V1
    /// `silent=1`: zero lines). ConfigLogger/LogMessage is the REAL
    /// ported row (log/messages.rs): the ladder emits through a
    /// driver-owned LogEngine; the FileService::is_* gates (:92/:95/
    /// :101) read env.svc (the FileService statics seam, 17q).
    pub fn show(&self, engine: &mut crate::log::messages::LogEngine, env: &FileEnvLite) {
        if let Some(cfg) = self.config.as_ref() {
            file_config_show(engine, &env.svc, cfg);
        }
    }
}

/// cc:87-:88 `unsigned get_file_adv_pub_id() { return file_adv_pub_id; }`
/// — the REAL getter over the cc:46 static (the 17w seam: file_lib.rs
/// file_lib.cc:658's publish site calls THIS, not the slot directly —
/// pub name stable across the swap).
pub fn get_file_adv_pub_id(env: &FileEnvLite) -> u32 {
    env.adv_pub_id.get()
}

/// cc:90-:117 `static void file_config_show(const FileConfig* fc)` —
/// the 18-caption ladder in the EXACT C call order: seven log_flag
/// sites (:92 enable_type [FileService static], :95 enable_signature
/// [static], :98 block_timeout_lookup [field], :101 enable_capture
/// [static], :114-:116 trace_type/trace_signature/trace_stream
/// [fields]) gating eleven log_value sites (:93 type_depth, :96
/// signature_depth, :99 block_timeout, :103-:106 the four capture
/// values, :109-:112 the unconditional tail trio + show_data_depth)
/// and three unconditional flag tails. The gate RETURNS decide the
/// value lines (messages.cc:364-:371 `return flag`). Overload map per
/// R4: i64 fields -> log_value_int (the `long` twin), the u64
/// max_files_per_flow -> log_value_uint. subopt=false everywhere (all
/// call sites default; the harness never arms a subopt line).
pub fn file_config_show(
    engine: &mut crate::log::messages::LogEngine,
    svc: &FileServiceLite,
    cfg: &Rc<RefCell<FileConfigLite>>,
) {
    use crate::log::messages::ConfigLogger;
    let c = cfg.borrow();
    if ConfigLogger::log_flag(engine, "enable_type", svc.is_file_type_id_enabled(), false) {
        ConfigLogger::log_value_int(engine, "type_depth", c.file_type_depth, false); // cc:93
    }
    if ConfigLogger::log_flag(engine, "enable_signature", svc.is_file_signature_enabled(), false) {
        // cc:96
        ConfigLogger::log_value_int(engine, "signature_depth", c.file_signature_depth, false);
    }
    if ConfigLogger::log_flag(engine, "block_timeout_lookup", c.block_timeout_lookup, false) {
        ConfigLogger::log_value_int(engine, "block_timeout", c.file_block_timeout, false); // cc:99
    }
    if ConfigLogger::log_flag(engine, "enable_capture", svc.is_file_capture_enabled(), false) {
        // cc:103-:106 (int64_t -> the `long` overload; the capture
        // block only ever rides this arm)
        ConfigLogger::log_value_int(engine, "capture_memcap", c.capture_memcap, false);
        ConfigLogger::log_value_int(engine, "capture_max_size", c.capture_max_size, false);
        ConfigLogger::log_value_int(engine, "capture_min_size", c.capture_min_size, false);
        ConfigLogger::log_value_int(engine, "capture_block_size", c.capture_block_size, false);
    }
    // cc:109-:112 (unconditional values)
    ConfigLogger::log_value_int(engine, "lookup_timeout", c.file_lookup_timeout, false);
    ConfigLogger::log_value_int(engine, "max_files_cached", c.max_files_cached, false);
    // cc:111 -- uint64_t field (file_config.h:66) -> the unsigned long twin
    ConfigLogger::log_value_uint(engine, "max_files_per_flow", c.max_files_per_flow, false);
    ConfigLogger::log_value_int(engine, "show_data_depth", c.show_data_depth, false);
    // cc:114-:116 (unconditional flag tails)
    ConfigLogger::log_flag(engine, "trace_type", c.trace_type, false);
    ConfigLogger::log_flag(engine, "trace_signature", c.trace_signature, false);
    ConfigLogger::log_flag(engine, "trace_stream", c.trace_stream, false);
}

// ------------------------------------------------------------------
// Module plumbing + the InspectApi record (cc:125-:175).
// ------------------------------------------------------------------

/// cc:131-:134 `static void file_init() { FileFlows::init(); }` — the
/// pinit slot; the round trip (file_flow_data_id 0->1 through the
/// harness FlowData::create_flow_data_id counter arm) rides the REAL
/// 17q body, file_flows FileFlows::init(env).
pub fn file_init(env: &mut FileEnvLite) {
    super::file_flows::FileFlows::init(env);
}

// (free-standing note, not a doc comment: the next doc block documents
// the record struct below, and these slots are deliberately absent.)
// The cc:136-:145 file_ctor/file_dtor slots: file_ctor == `FileInspect::new`
// over the module's config slot; file_dtor == the Rc drop chain. The
// V7 wiring arm in the replay drives exactly new -> drop (the real
// dtor frees the heap steal — R2 safe) and NEVER mod_ctor/mod_dtor
// (the FileIdModule vtable hole, R3: `new FileIdModule`/`delete m`
// ride file_module.cc, an unported row — presence documented, never
// called, never faked).

/// cc:147-:173 `static const InspectApi file_inspect_api` — the record
/// as DATA: fn-pointer slots become presence bools (the V7_api pins),
/// `sizeof(InspectApi)` stays the 152 probe pin, the null SnbBufList
/// pointer is an Option. `mod_ctor`/`mod_dtor` (the BaseApi module
/// slots) carry no Rust counterpart (R3) — documented, absent.
pub struct InspectApiRecord {
    pub ptype: u32,        // PlugType
    pub size: usize,       // sizeof(InspectApi) -- probe pin (never size_of)
    pub api_version: u32,  // ((BASE_API_VERSION << 16) | 5)
    pub version: u32,
    pub features: u64,     // API_RESERVED
    pub options: u32,      // API_OPTIONS
    pub name: &'static str,
    pub help: &'static str,
    pub itype: u32,        // InspectorType
    pub proto_bits: u32,
    pub buffers: Option<()>, // `SnbBufList* buffers` -- nullptr in C
    pub service: &'static str,
    // fn-pointer slots (presence = the V7_api 0/1 pins):
    pub pinit: bool, // file_init -> `file_init` above
    pub pterm: bool,
    pub tinit: bool,
    pub tterm: bool,
    pub ctor: bool, // file_ctor -> FileInspect::new
    pub dtor: bool, // file_dtor -> drop
    pub ssn: bool,
    pub reset: bool,
}

/// cc:175 `const BaseApi* sin_file_flow = &file_inspect_api.base;` —
/// the global (file_log.cc:322 is its upstream consumer, the 18+
/// file_log row). BaseApi is the record's prefix by construction of
/// the C struct; the Rust twin states the same field values directly
/// (no reinterpret-cast prefix trick needed).
pub const SIN_FILE_FLOW: InspectApiRecord = InspectApiRecord {
    ptype: PT_INSPECTOR,
    size: PROBE_SIZEOF_INSPECT_API,
    api_version: INSAPI_VERSION,
    version: 0,
    features: API_RESERVED,
    options: API_OPTIONS,
    name: FILE_ID_NAME, // "file_inspect" (17u canonical home)
    help: FILE_ID_HELP, // "configure file inspection"
    itype: IT_PASSIVE,
    proto_bits: PROTO_BIT__NONE,
    buffers: None,
    service: "file", // cc:164
    pinit: true,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true,
    dtor: true,
    ssn: false,
    reset: false,
};
