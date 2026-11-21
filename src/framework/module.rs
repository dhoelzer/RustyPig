//! Port of `src/framework/module.{h,cc}` (ground truth @ fe29cbe: module.cc
//! 403 L md5 `9608434cb5d1820d6033a32632080499` + module.h 283 L md5
//! `e1c35b873644dac5b00d0fc5e5c903ba`) — row 19a, the chapter-19 OPENER
//! (framework/ + main/ misc9 pick P1, tools/misc9_harness/PLAN.md §1/§3).
//!
//! THE DEBT THIS ROW CLOSES (cite-never-carry law): `file_module.rs:75` and
//! `file_module.rs:232-234` recorded at 17z/18a — "NO Rust Module base forked
//! (the 17z ruling — the REAL framework/module.o closes it harness-side)".
//! This row lands that base (PLAN §3 landing map: `src/framework/module.rs`).
//!
//! THE DONOR-VERBATIM FACE: the harness copy tree carries
//! `tools/misc9_harness/copy/framework/module.cc` byte-ident to the ground
//! (`md5 == 9608434c…` asserted EVERY build — build.sh; the FIRST row of the
//! port whose 403-L half needs ZERO cps; PLAN §9). The residue face that the
//! harness proved (receipt `module_residue_dem.txt`: EXACTLY 3 demangled
//! pulls — `show_stats` scalar + `ThreadConfig::get_instance_max` +
//! `ThreadConfig::get_instance_id`) closes here as three cited seams: the
//! `::show_stats` renderer call sites (utils/stats renderer NOT landed —
//! cited-never-called, 18l/18n posture), init_stats' `instance_max` input
//! (the witness_conf 4dd91018 heredoc face, ported as an explicit param),
//! and `get_instance_id` (the 17l thread-static lesson; the landed
//! ThreadState.instance_id twin, main/thread.rs:28-:31).
//!
//! Deviations (full text in KNOWN DEVIATIONS.md, row 19a):
//! - C++ virtual dispatch (module.h :92-:222 default virtuals) lands as an
//!   explicit trait, [`ModuleVirt`] (the response_buf.rs ControlConn/LogSink
//!   posture, cited lineage); base methods take the live `get_counts()`
//!   slice as an explicit param where C fetches it inside (borrow law).
//! - THE -DNDEBUG PRODUCTION ARM (harness law, PLAN §9): the graph the
//!   harness builds compiles -DNDEBUG — the ground production arm — and it is
//!   the ONLY arm where module.cc :372 `assert(false); // wrong name =
//!   programmer error` falls through to :373 `return 0;` OBSERVABLE (vectors
//!   `MS ggc hit=13 miss=0`). Cargo builds are never given -DNDEBUG, so the
//!   port models the PRODUCTION arm unconditionally (the 18d DEBUG_MSGS
//!   "autotools flag != cargo cfg" precedent) and keeps the assert faces as
//!   debug_assert!: [`Module::get_global_count`].
//! - nullptr-vs-emptiness: C gates on raw pointers (`!p`, `!q`, `!pegs`);
//!   the Rust model reads Option/empty per the landed panic-free posture
//!   (framework/codec.rs:530 "panic-free instead of UB") — an out-of-range
//!   C index is BOUND-CLAMPED to the table, NEVER a panic.
//! - `enum Usage`/`RuleMap` residents are NEVER re-authored here: the Usage
//!   order constants and [`RuleMap`] landed at 18d (codec_module.rs
//!   :253-:259 / :273-:278 — the "framework/module.h:77-:81" cite lives
//!   THERE) and this row imports them (PLAN §3 residents rule).
//! - `Parameter` stays the 16c landed shape (framework/parameter.rs:
//!   name/ptype/deflt slots; the C 5-slot sentinel row at module.cc :34
//!   cites range+help slots that stay unported there).

use crate::codecs::codec_module::{C_USAGE_CONTEXT, RuleMap};
use crate::framework::counts::{CountType, PegCount, PegInfo};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::value::Value;

// ==================================================================
// null_params — module.cc :32-:35
// `static const Parameter null_params[] = { { nullptr, Parameter::PT_MAX,
//   nullptr, nullptr, nullptr } };`
// THE one-identity static (the C `static const` face — `pub static` so
// init's install and the caller's window share ONE address, the
// ptr-identity pin in the parity census): the hidden static of module.o
// the FACE-A probe walks for real (init :59 `params = null_params;` ->
// get_parameters module.h :136): `NULLWALK entries=0 sentinel_type=21` —
// zero rows before the name-null sentinel, and the sentinel's Type ordinal
// is PT_MAX = 21 by the parameter.h enum walk (framework/parameter.rs
// Type::PtMax; the harness PYPIN re-walks the ground header every build).
// ==================================================================
pub static NULL_PARAMS: [Parameter; 1] = [Parameter {
    name: None,                    // cc:34 `{ nullptr,`
    ptype: PtType::PtMax,          // cc:34 `Parameter::PT_MAX,`
    deflt: None,                   // dflt slot; range+help stay 16c-unported
}];

// ==================================================================
// simple_pegs — module.cc :396-:403 `namespace snort { const PegInfo
// simple_pegs[] = { { CountType::SUM, "packets", "total packets" },
// { CountType::END, nullptr, nullptr } }; }` — THE definition home (the
// counts.h:55 extern cite stays in counts.rs; its row-6 deferral note
// "simple_pegs[] … deferred with that layer" closes HERE, definition-home
// law). vectors lines 39-41 exercise it (SP rows: 1 real peg + END
// sentinel -> num_counts=1; the "packets" get_global_count name-hit).
// The C `{ nullptr, nullptr }` terminator lands as name:"" help:"" — the
// landed PegInfo face (file_log.rs:174-:177 terminator twin).
// ==================================================================
pub static SIMPLE_PEGS: [PegInfo; 2] = [
    // cc:400 VERBATIM (`{ CountType::SUM, "packets", "total packets" },` —
    // the harness PYPIN re-asserts this exact row text):
    PegInfo { peg_type: CountType::Sum, name: "packets", help: "total packets" },
    // cc:401 `{ CountType::END, nullptr, nullptr }`:
    PegInfo { peg_type: CountType::End, name: "", help: "" },
];

// ==================================================================
// Command — module.h :65-:75 + Command::get_arg_list (module.cc :37-:50,
// the struct's only out-of-line method). `LuaCFunction = int(*)(
// lua_State*)` (h:63) lands as a data-free liveness token (the 18a
// LuaCFunction posture: no lua_State type in the Rust tree; the FACE-A
// probes carry func=null anyway).
// ==================================================================
pub struct LuaCFunctionToken;

pub struct Command {
    pub name: Option<&'static str>,               // h:67
    pub func: Option<&'static LuaCFunctionToken>, // h:68 (token posture, 18a)
    pub params: Option<&'static [Parameter]>,     // h:69 `const Parameter*`
    pub help: Option<&'static str>,               // h:70
    pub can_run_in_parallel: bool,                // h:72 NSDMI `= false`
}

impl Command {
    /// module.cc :37-:50 — `args = "("; const Parameter* p = params;
    /// while ( p and p->name ) { if ( p != params ) args += ", "; args +=
    /// p->name; ++p; } args += ")";` The `p != params` guard (:44) skips the
    /// joiner before the FIRST name; the `p and p->name` gate (:42) stops AT
    /// the name-null sentinel (FACE-A face: null_params -> `()`; the
    /// two-name table -> `(one, two)`; a null params ptr -> `()`).
    pub fn get_arg_list(&self) -> String {
        let mut args = String::from("("); // cc:39
        if let Some(params) = self.params {
            for (n, p) in params.iter().enumerate().take_while(|(_, p)| p.name.is_some()) {
                if n != 0 {
                    args.push_str(", "); // cc:44-:45 `if ( p != params ) args += ", "`
                }
                args.push_str(p.name.unwrap_or("")); // cc:46 (name Some by the :42 gate)
            }
        }
        args.push(')'); // cc:49
        args
    }
}

// ==================================================================
// The virtuals (module.h :83-:222) — C++ dispatch as an explicit trait
// (deviation row 19a; response_buf.rs:56-:60 ControlConn/LogSink lineage).
// EVERY default body mirrors the C default VERBATIM (line cite beside it);
// the FACE-A DEFS census walks exactly these default arms (all-null/false +
// gid=0 + usage=1).
// ==================================================================
pub trait ModuleVirt {
    /// h:92-:93 `virtual bool begin(const char*, int, SnortConfig*)
    /// { return true; }`
    fn begin(&self, _fqn: &str, _idx: i32) -> bool {
        true
    }
    /// h:95-:96 `virtual bool end(const char*, int, SnortConfig*)
    /// { return true; }`
    fn end(&self, _fqn: &str, _idx: i32) -> bool {
        true
    }
    /// h:98-:99 `virtual bool set(const char*, Value&, SnortConfig*)
    /// { return true; }` — the base default NEVER reads the Value& (the
    /// FACE-A `Value v(true)` rides framework/value.rs::from_bool; set
    /// default true feeds `VERB table set=1`).
    fn set(&self, _fqn: &str, _v: &mut Value) -> bool {
        true
    }
    /// h:101 `virtual void set_trace(const Trace*) const { }` — the Trace
    /// type stays unported (18a TraceToken posture); base no-op face.
    fn set_trace(&self, _trace_present: bool) {}
    /// h:103-:104 `virtual const TraceOption* get_trace_options() const
    /// { return nullptr; }` — returns TRUE == non-null; base nullptr face.
    fn get_trace_options(&self) -> bool {
        false
    }
    /// h:107-:108 `virtual bool matches(const char* /*param_name*/,
    /// std::string& /*lua_name*/) { return false; }`
    fn matches(&self, _param_name: &str) -> bool {
        false
    }
    /// h:111-:112 `virtual unsigned get_gid() const { return 0; }`
    fn get_gid(&self) -> u32 {
        0
    }
    /// h:139-:140 `virtual const Command* get_commands() const
    /// { return nullptr; }`
    fn get_commands(&self) -> Option<&'static [Command]> {
        None
    }
    /// h:142-:143 `virtual const RuleMap* get_rules() const
    /// { return nullptr; }` (RuleMap = the imported 18d resident,
    /// codec_module.rs:253 — NEVER re-authored here, PLAN §3).
    fn get_rules(&self) -> Option<&'static [RuleMap]> {
        None
    }
    /// h:145-:146 `virtual const PegInfo* get_pegs() const { return
    /// nullptr; }` — the stats family's read face (MS/SP DEC rows carry
    /// non-null tables; the DEFS census arm pins the null default).
    fn get_pegs(&self) -> Option<&'static [PegInfo]> {
        None
    }
    /// h:148-:149 `virtual bool counts_need_prep() const { return false; }`
    fn counts_need_prep(&self) -> bool {
        false
    }
    /// h:151 `virtual void prep_counts(bool) { }`
    fn prep_counts(&self, _new_thread: bool) {}
    /// h:154-:155 `virtual PegCount* get_counts() const { return nullptr; }`
    /// — the const method returning a NON-const pointer (the probe's
    /// const_cast face, probe_dec.cc:37). Rust cannot alias &mut through
    /// &self: the landed deviation models the SAME non-const access with a
    /// `&mut self` receiver (const-cast interiors are unsound; deviation
    /// row 19a); the base uses it ONLY as the `if ( !p )` null gate at
    /// cc:76/:169/:343 — the live cells ride the explicit &mut slice params.
    /// C default nullptr -> Rust default None.
    fn get_counts(&mut self) -> Option<&mut [PegCount]> {
        None
    }
    /// the free `get_instance_id()` the stats/index sites call (C
    /// main/thread.h THREAD_LOCAL face — the 17l lesson, thread.cc:45-:47
    /// run_num/instance_id/thread_type; the landed twin lives at
    /// main/thread.rs ThreadState.instance_id). Harness face: single
    /// instance -> 0 (the instance-0 rows pinned by the vectors).
    fn get_instance_id(&self) -> u32 {
        0
    }
    /// h:162-:163 `virtual ProfileStats* get_profile() const { return
    /// nullptr; }` — ProfileStats has NO landed Rust type (18a data-free
    /// token posture); TRUE == non-null, base nullptr face.
    fn get_profile(&self) -> bool {
        false
    }
    /// h:166-:168 the (index, name-out, parent-out) overload "implement
    /// above -or- below" (h:165 comment face).
    fn get_profile_at(
        &self,
        _index: u32,
        _name: &mut Option<&'static str>,
        _parent: &mut Option<&'static str>,
    ) -> bool {
        false // nullptr face
    }
    /// h:170-:171 `virtual const char* get_defaults() const { return
    /// nullptr; }`
    fn get_defaults(&self) -> Option<&'static str> {
        None
    }
    /// h:173-:174 `virtual bool global_stats() const { return false; }`
    fn global_stats(&self) -> bool {
        false
    }
    /// h:176-:179 "Return true only if all of the module's stats are
    /// aggregated into another module."
    fn stats_are_aggregated(&self) -> bool {
        false
    }
    /// h:181-:184 "Return true only if all of the module's stats are
    /// aggregated from other modules."
    fn is_aggregator(&self) -> bool {
        false
    }
    /// h:192-:193 `virtual bool has_dynamic_stats() const { return false; }`
    /// (h:194 collect_dynamic_stats(stats::Builder&, DynamicStatsPolicy&)
    /// stays cite-only — the stats::Builder layer is unported, same posture
    /// as the ::show_stats renderer).
    fn has_dynamic_stats(&self) -> bool {
        false
    }
    /// h:216 `enum Usage { GLOBAL, CONTEXT, INSPECT, DETECT };` order pins
    /// ride the 18d landed consts (codec_module.rs:273-:278 — the module.h
    /// cite lives THERE); h:218-:219 base default = CONTEXT = 1 (FACE-A
    /// DEFS `usage=1`).
    fn get_usage(&self) -> u32 {
        C_USAGE_CONTEXT
    }
    /// h:221-:222 `virtual bool is_bindable() const { return false; }`
    fn is_bindable(&self) -> bool {
        false
    }
}

// ==================================================================
// class Module — module.h :83-:281. The h:23-:35 class doc ("There is at
// most one instance of a Module at any time… Module will set all parameter
// defaults immediately after calling begin()… there are no internal default
// lists") is a doc face, not code.
// ==================================================================
pub struct Module {
    // module.h :274-:279 privates (`friend ModuleManager` h:270 has no Rust
    // face — the manager layer is unported).
    name: Option<&'static str>,                // h:274 `const char* name;`
    help: Option<&'static str>,                // h:275
    params: Option<&'static [Parameter]>,      // h:277 `const Parameter* params;`
    list: bool,                                // h:278 `bool list;`
    table_level: i32,                          // h:279 NSDMI `= 0`

    // module.h :230-:234 protected stats state (probe Dec's rows()/cell()/
    // dcell() helpers read exactly these):
    pub dump_stats_initialized: Vec<u32>,      // h:230 `vector<unsigned>`
    pub counts: Vec<Vec<PegCount>>,            // h:231
    pub dump_stats_counts: Vec<Vec<PegCount>>, // h:232
    pub dump_stats_results: Vec<PegCount>,     // h:233
    pub num_counts: i32,                       // h:234 NSDMI `= -1`
}

impl Module {
    /// module.cc :53-:60 — the private init (h:271, default h = nullptr):
    /// `name = s; help = h; list = false; num_counts = -1; params =
    /// null_params;` THE null_params install site (:59 — the FACE-A order
    /// cite `nullwalk:table:32->init:59->get:136`).
    fn init(&mut self, s: Option<&'static str>, h: Option<&'static str>) {
        self.name = s;                        // cc:55
        self.help = h;                        // cc:56
        self.list = false;                    // cc:57
        self.num_counts = -1;                 // cc:58
        self.params = Some(&NULL_PARAMS); // cc:59 `params = null_params;` (the one-identity static)
    }

    /// module.cc :62-:63 `Module::Module(const char* s, const char* h)
    /// { init(s, h); }` (protected ctor h:225-:226; FACE-A ProbeModule a).
    pub fn new(name: &'static str, help: &'static str) -> Module {
        let mut m = Module::blank();
        m.init(Some(name), Some(help)); // cc:63
        m
    }

    /// module.cc :65-:70 — the params ctor (h:226 `bool is_list = false`
    /// NSDMI pair): `init(s, h); list = is_list; params = p;` (FACE-A b
    /// false / c true over the two_params face).
    pub fn new_params(
        name: &'static str,
        help: &'static str,
        p: Option<&'static [Parameter]>,
        is_list: bool,
    ) -> Module {
        let mut m = Module::blank();
        m.init(Some(name), Some(help)); // cc:67
        m.list = is_list;               // cc:68
        m.params = p;                   // cc:69
        m
    }

    /// the pre-init shell ONLY (every real ctor funnels through init; the
    /// field defaults mirror the h:234/:279 NSDMIs).
    fn blank() -> Module {
        Module {
            name: None,
            help: None,
            params: None,
            list: false,
            table_level: 0,             // h:279
            dump_stats_initialized: Vec::new(),
            counts: Vec::new(),
            dump_stats_counts: Vec::new(),
            dump_stats_results: Vec::new(),
            num_counts: -1,             // h:234
        }
    }

    // ---- inline accessors (module.h) ---------------------------------

    /// h:114-:115 `get_name()` — `return name ? name : params->name;` (the
    /// Parameter-name fallback; FACE-A REC rows all carry a name).
    pub fn get_name(&self) -> Option<&'static str> {
        match self.name {
            Some(n) => Some(n),
            None => self.params.and_then(|p| p.first().and_then(|p| p.name)), // h:115 params->name
        }
    }
    /// h:117-:118 `is_table()` — `(name != nullptr)`.
    pub fn is_table(&self) -> bool {
        self.name.is_some()
    }
    /// h:120-:121 `is_list()` — the `list` slot (init :57 false; new_params
    /// :68).
    pub fn is_list(&self) -> bool {
        self.list
    }
    /// h:123-:131 `get_type()` — list -> PT_LIST (:125-:126), table ->
    /// PT_TABLE (:127-:128), else params->type (:130). FACE-A REC pin: a/b
    /// is_table type=0 (PtTable), c type=1 (PtList).
    pub fn get_type(&self) -> PtType {
        if self.is_list() {
            PtType::PtList
        } else if self.is_table() {
            PtType::PtTable
        } else {
            self.params
                .and_then(|p| p.first())
                .map(|p| p.ptype) // h:130 params->type
                .unwrap_or(PtType::PtMax)
        }
    }
    /// h:133-:134 `get_help()`.
    pub fn get_help(&self) -> Option<&'static str> {
        self.help
    }
    /// h:136-:137 `get_parameters()` — THE window onto the hidden
    /// null_params static (the FACE-A NULLWALK head).
    pub fn get_parameters(&self) -> Option<&'static [Parameter]> {
        self.params
    }
    /// h:159-:160 `virtual int get_num_counts() const { return num_counts; }`
    pub fn get_num_counts(&self) -> i32 {
        self.num_counts
    }
    /// h:228-:229 protected `set_params`.
    pub fn set_params(&mut self, p: Option<&'static [Parameter]>) {
        self.params = p;
    }

    // ---- the stats family (module.cc :72-:374) ------------------------

    /// module.cc :72-:94 — `p = get_counts(); if ( !p ) return;`
    /// (:74-:77); `q = get_pegs(); assert(q);` (:79-:81); the double loop
    /// (:82-:93): for each dump row, for i < num_counts, `if (
    /// q[i].type == CountType::NOW )` zeroes dump_stats_counts (:88), counts
    /// (:89) and dump_stats_results (:90).
    pub fn clear_global_active_counters<V: ModuleVirt + ?Sized>(&mut self, v: &mut V) {
        if v.get_counts().is_none() {
            return; // cc:76-:77
        }
        let q = match v.get_pegs() {
            Some(q) => q,
            None => {
                debug_assert!(false, "module.cc:81 assert(q)"); // NDEBUG arm elides; panic-free clamp posture
                return;
            }
        };
        let n = self.num_counts.max(0) as usize;
        let n = n.min(q.len()); // bound-clamp (C indexed q[i] unchecked)
        let now_i = nows(q, n); // cc:86 filter computed once
        for row in &mut self.dump_stats_counts {
            // cc:82 loop head `thread_index < dump_stats_counts.size()`
            for &i in &now_i {
                row[i] = 0; // cc:88
            }
        }
        for row in &mut self.counts {
            for &i in &now_i {
                row[i] = 0; // cc:89
            }
        }
        for &i in &now_i {
            if i < self.dump_stats_results.len() {
                self.dump_stats_results[i] = 0; // cc:90
            }
        }
    }

    /// module.cc :96-:107 — `q = get_pegs(); if ( !q ) return;` (:98-:101);
    /// `if ( global_stats() ) return;` (:103-:104); then
    /// `aggregate_dump_stats_counts(q, num_counts, dump_stats_counts,
    /// dump_stats_results)` (:106 — the field-to-field aggregate; vectors
    /// `MS ggc hit=13` = the results the aggregate left).
    pub fn main_accumulate_stats<V: ModuleVirt + ?Sized>(&mut self, v: &V) {
        let q = match v.get_pegs() {
            Some(q) => q,
            None => return, // cc:100-:101
        };
        if v.global_stats() {
            return; // cc:103-:104
        }
        let n = self.num_counts;
        let dsc = self.dump_stats_counts.clone(); // cc:106 reads the field; the borrow splits clone-cheap (deviation row 19a, values identical)
        Module::aggregate_dump_stats_counts(q, n, &dsc, &mut self.dump_stats_results); // cc:106
    }

    /// module.cc :109-:124 — the by-value-rows overload (h:200-:204):
    /// `if ( !pegs || num_counts <= 0 ) return;` (:115-:116),
    /// ptrs.reserve + emplace_back per row (:118-:121), forward (:123).
    pub fn aggregate_dump_stats_counts(
        pegs: &[PegInfo],
        num_counts: i32,
        per_thread_counts: &[Vec<PegCount>],
        out: &mut Vec<PegCount>,
    ) {
        if pegs.is_empty() || num_counts <= 0 {
            return; // cc:115 `!pegs || num_counts <= 0`
        }
        let ptrs: Vec<Option<&Vec<PegCount>>> = per_thread_counts.iter().map(Some).collect();
        // cc:118-:121 `ptrs.emplace_back(&counts)` (Some = the non-null ptr face)
        Module::aggregate_dump_stats_counts_ptrs(pegs, num_counts, &ptrs, out); // cc:123
    }

    /// module.cc :126-:161 — the pointer overload (h:205-:209): `out.assign
    /// (num_counts, 0)` (:135); per row, `if ( !counts || (int)counts->
    /// size() != num_counts ) continue;` (:139-:140); per peg the switch
    /// (:144-:158): END :146-:147 no-op; SUM **shared with NOW**
    /// `out[peg_idx] += (*counts)[peg_idx]` (:149-:152 — the C fall-through
    /// case PAIR, transcribed as one Rust arm pair); MAX keeps the larger
    /// (:154-:157).
    pub fn aggregate_dump_stats_counts_ptrs(
        pegs: &[PegInfo],
        num_counts: i32,
        per_thread_counts: &[Option<&Vec<PegCount>>],
        out: &mut Vec<PegCount>,
    ) {
        if pegs.is_empty() || num_counts <= 0 {
            return; // cc:132-:133
        }
        out.clear();
        out.resize(num_counts as usize, 0); // cc:135 std::vector::assign(n, 0)
        for counts in per_thread_counts {
            // cc:139-:140 the null-or-short-size skip
            let row = match counts {
                Some(r) if r.len() as i32 == num_counts => r,
                _ => continue,
            };
            let pegs_n = pegs.len();
            for (peg_idx, cell) in row.iter().enumerate() {
                // cc:142 `peg_idx < num_counts` — size already == num_counts
                if peg_idx >= pegs_n {
                    break; // bound-clamp (C read pegs[peg_idx] unchecked)
                }
                match pegs[peg_idx].peg_type {
                    CountType::End => {} // cc:146-:147
                    CountType::Sum | CountType::Now => {
                        // cc:149-:152 the shared SUM/NOW pair
                        out[peg_idx] += cell;
                    }
                    CountType::Max => {
                        // cc:154-:157
                        if *cell > out[peg_idx] {
                            out[peg_idx] = *cell;
                        }
                    }
                }
            }
        }
    }

    /// module.cc :164-:224 — THE stats ladder (the DEC face). `if (
    /// num_counts < 0 ) init_stats();` (:166-:167, new_thread=false default
    /// h:190); `p = get_counts(); q = get_pegs(); if ( !p ) return;
    /// assert(q);` (:169-:175); `instance_id = get_instance_id()` (:177);
    /// first-dump face (:178-:182): dump_stats && flag==0 -> COPY
    /// counts[instance] into dump_stats_counts[instance] and set the flag
    /// (vectors `MS sum-true cell0=7 dcell0=10 p0=3`: dcell = copy(7)+add(3)
    /// = 10 — the copy rode BEFORE the add); global_stats arm (:184-:195)
    /// the each-thread-same-variable direct-assigned face; else the switch
    /// (:198-:222): END :202-:203; SUM `add_peg_count(i, p[i], dump_stats)`
    /// (:206) THEN `if (!dump_stats) p[i] = 0` (:207-:208 — the
    /// ADD-BEFORE-CLEAR order the harness PYPIN re-measures,
    /// `add:cc206-before-clear:cc208`); NOW dumps ONLY (:211-:214 — live p
    /// NEVER cleared, vectors `MS reset … p1=5-survives` chain); MAX
    /// `set_max_peg_count` THEN clear-if-not-dumping (:216-:220;
    /// `dcell2=9` = the 2>9 FALSE keep face). The live counts slice `p`
    /// arrives as the explicit param where C fetches get_counts() inside
    /// (:169 — borrow law, deviation row 19a).
    pub fn sum_stats<V: ModuleVirt + ?Sized>(
        &mut self,
        v: &V,
        p: &mut [PegCount],
        dump_stats: bool,
    ) {
        if self.num_counts < 0 {
            self.init_stats(v, false); // cc:166-:167
        }
        let q = v.get_pegs();
        // cc:172-:173 `if ( !p ) return;` — the empty-slice ~ null-ptr face
        // (a live C module NEVER hands an empty non-null counts table).
        if p.is_empty() {
            return;
        }
        // cc:175 `assert(q);` — NDEBUG production arm falls through;
        // a null-q switch in C is UB; the Rust model clamps to the table.
        let q = match q {
            Some(q) => q,
            None => {
                debug_assert!(false, "module.cc:175 assert(q)");
                return;
            }
        };
        let instance_id = v.get_instance_id() as usize; // cc:177
        // cc:178-:182 THE first-dump copy face (sum_stats(true) on a fresh
        // instance copies the live row into the dump row FIRST):
        if dump_stats && self.dump_stats_initialized.get(instance_id).copied() == Some(0) {
            self.dump_stats_counts[instance_id] = self.counts[instance_id].clone(); // cc:180
            self.dump_stats_initialized[instance_id] = 1; // cc:181
        }
        let n = self.num_counts.max(0) as usize;
        if v.global_stats() {
            // cc:186-:194 "each thread update the same variable" — the
            // direct-assigned face (dump -> dump_stats_results[i] (:191),
            // live -> counts[0][i] (:193), the global single-row face).
            for (i, cell) in p.iter().enumerate().take(n) {
                if dump_stats {
                    if i < self.dump_stats_results.len() {
                        self.dump_stats_results[i] = *cell; // cc:191
                    }
                } else if !self.counts.is_empty() && i < self.counts[0].len() {
                    self.counts[0][i] = *cell; // cc:193
                }
            }
        } else {
            let n = n.min(q.len()); // bound-clamp vs the C unchecked q[i]
            for i in 0..n {
                match q[i].peg_type {
                    CountType::End => {} // cc:202-:203
                    CountType::Sum => {
                        self.add_peg_count(i, p[i], dump_stats, v.get_instance_id()); // cc:206 ADD FIRST
                        if !dump_stats {
                            p[i] = 0; // cc:207-:208 THEN clear
                        }
                    }
                    CountType::Now => {
                        // cc:211-:214 the dump-guarded add ONLY
                        if dump_stats {
                            self.add_peg_count(i, p[i], dump_stats, v.get_instance_id()); // cc:213
                        }
                    }
                    CountType::Max => {
                        self.set_max_peg_count(i, p[i], dump_stats, v.get_instance_id()); // cc:217
                        if !dump_stats {
                            p[i] = 0; // cc:218-:219
                        }
                    }
                }
            }
        }
    }

    /// module.cc :226-:270 — the collect face (cited-never-vectored by the
    /// misc9 DEC probe; still fully ported + unit-pinned): gates
    /// `!p || !q || num_counts <= 0 -> out.clear()` (:234-:238); `out.
    /// assign` (:240); global direct-copy-then-return (:242-:247);
    /// `if ( instance_id >= counts.size() ) return;` (:249-:251 the
    /// stale-instance face); SUM/NOW `out[i] = counts[instance][i] + p[i]`
    /// (:262); MAX keeps max (:266 — the ternary face).
    pub fn collect_dump_stats_counts<V: ModuleVirt + ?Sized>(
        &mut self,
        v: &V,
        p: &mut [PegCount],
        out: &mut Vec<PegCount>,
    ) {
        if self.num_counts < 0 {
            self.init_stats(v, false); // cc:228-:229
        }
        let q = v.get_pegs();
        if p.is_empty() || q.is_none() || self.num_counts <= 0 {
            out.clear(); // cc:234-:237
            return;
        }
        let q = q.unwrap();
        out.clear();
        out.resize(self.num_counts as usize, 0); // cc:240 std::vector::assign(n, 0)
        if v.global_stats() {
            for (i, cell) in p.iter().enumerate().take(self.num_counts as usize) {
                out[i] = *cell; // cc:244-:245
            }
            return; // cc:246
        }
        let instance_id = v.get_instance_id() as usize; // cc:249
        if instance_id >= self.counts.len() {
            return; // cc:250-:251
        }
        let n = (self.num_counts as usize).min(q.len()).min(self.counts[instance_id].len());
        for i in 0..n {
            match q[i].peg_type {
                CountType::End => {} // cc:257-:258
                CountType::Sum | CountType::Now => {
                    out[i] = self.counts[instance_id][i] + p[i]; // cc:260-:263
                }
                CountType::Max => {
                    // cc:265-:267 `(p[i] > counts[...]) ? p[i] : counts[...]`
                    out[i] = if p[i] > self.counts[instance_id][i] {
                        p[i]
                    } else {
                        self.counts[instance_id][i]
                    };
                }
            }
        }
    }

    /// module.cc :272-:284 — init-if-negative (:274-:275), the two size
    /// gates (:277-:281), then the copy (:283).
    pub fn set_dump_stats_results<V: ModuleVirt + ?Sized>(
        &mut self,
        v: &V,
        results: &[PegCount],
    ) {
        if self.num_counts < 0 {
            self.init_stats(v, false); // cc:274-:275
        }
        if self.num_counts <= 0 {
            return; // cc:277-:278
        }
        if results.len() as i32 != self.num_counts {
            return; // cc:280-:281 `(int)results.size() != num_counts`
        }
        self.dump_stats_results = results.to_vec(); // cc:283
    }

    /// module.cc :286-:289 — the dump_results window (the get_global_count
    /// :370 consumer reads exactly this).
    pub fn get_dump_stats_results(&self) -> &[PegCount] {
        &self.dump_stats_results // cc:288
    }

    /// module.cc :291-:295 — `if ( num_counts > 0 )
    /// dump_stats_initialized.assign(dump_stats_initialized.size(), 0);` —
    /// re-arms the first-dump face for every instance.
    pub fn clear_dump_stats_state(&mut self) {
        if self.num_counts > 0 {
            let n = self.dump_stats_initialized.len();
            self.dump_stats_initialized.clear();
            self.dump_stats_initialized.resize(n, 0); // cc:294 assign(size(), 0) face
        }
    }

    /// module.cc :297-:301 — `if ( num_counts > 0 ) ::show_stats(get_counts
    /// (), get_pegs(), peg_idxs, get_name(), fh)`. The `::show_stats`
    /// renderer (utils/stats.cc) is NOT a landed Rust layer — the call site
    /// rides cited-NEVER-ported (18l/18n cited-family posture; the harness
    /// proved `show_stats` among the ONLY 3 residue pulls of module.o —
    /// receipt module_residue_dem.txt, witness_conf 4dd91018 heredoc home).
    /// This models the GUARD face only; returns whether the C renderer call
    /// WOULD fire.
    pub fn show_interval_stats_guard<V: ModuleVirt + ?Sized>(&self, v: &mut V) -> bool {
        // cc:299 `if ( num_counts > 0 )` (:300 the cited renderer call needs
        // counts+pegs live in C — the guard face only here)
        self.num_counts > 0 && v.get_counts().is_some() && v.get_pegs().is_some()
    }

    /// module.cc :303-:310 — `if ( num_counts > 0 ) { ::show_stats(&
    /// dump_stats_results[0], get_pegs(), num_counts, get_name());
    /// clear_dump_stats_state(); }` — the renderer cited-never-land (same
    /// face); the STATE-CLEAR half (:308) is REAL and ported. Returns
    /// whether the C arm ran.
    pub fn show_stats_and_clear(&mut self) -> bool {
        if self.num_counts > 0 {
            // cc:307 ::show_stats(&dump_stats_results[0], ...) CITED only
            self.clear_dump_stats_state(); // cc:308
            true
        } else {
            false
        }
    }

    /// module.cc :312-:336 — `pegs = get_pegs(); if ( !pegs ) return;`
    /// (:314-:317); `if ( num_counts <= 0 ) { num_counts = 0; while (
    /// pegs[num_counts].name ) ++num_counts; }` (:319-:325 — the walk stops
    /// BEFORE the name-null END sentinel: four_pegs -> 3, simple_pegs -> 1;
    /// the harness vectors' MS `num_counts=3` / SP `num_counts=1` face
    /// pair); `number_of_threads = new_thread ? 1 : ThreadConfig::
    /// get_instance_max()` (:327 — the witness_conf heredoc pull; ported as
    /// the explicit param below, the landed ThreadState.instance_max twin
    /// main/thread.rs:31); per thread emplace_back(num_counts) x2 +
    /// push_back(0) (:329-:334); `dump_stats_results.resize(num_counts)`
    /// Vectors pin: `MS init-true … rows=1` (new_thread=true -> NO
    /// ThreadConfig pull) vs `MS init-false rows=2` (the second call
    /// APPENDS witness value 1 more row — cc:329-:334 emplace_back, the
    /// rows-grow face; witness_conf 4dd91018's get_instance_max returns 1).
    pub fn init_stats<V: ModuleVirt + ?Sized>(&mut self, v: &V, new_thread: bool) {
        // the harness ground face: ThreadConfig::get_instance_max() == the
        // witness_conf value; callers holding a ThreadState pass it through
        // init_stats_with_max (main/thread.rs seam).
        self.init_stats_with_max(v, new_thread, 1);
    }

    /// the param-exposed face (the ThreadConfig::get_instance_max seam — the
    /// §2 residue pull closed as a param, witness_conf 4dd91018 lineage).
    /// THE harness face: witness_conf's body returns 1, and init_stats on an
    /// ALREADY-initialized module APPENDS instance_max more rows (cc:329-:334
    /// emplace_back loop) — the vectors' `MS init-false rows=2` = 1 existing
    /// + 1 appended, num_counts KEPT (the :319 gate skips the walk).
    pub fn init_stats_with_max<V: ModuleVirt + ?Sized>(
        &mut self,
        v: &V,
        new_thread: bool,
        instance_max: u32,
    ) {
        let pegs = match v.get_pegs() {
            Some(p) => p,
            None => return, // cc:316 `if ( !pegs ) return;`
        };
        if self.num_counts <= 0 {
            // cc:319-:325 the name-walk (`while ( pegs[num_counts].name )` —
            // the landed "" sentinel face, file_log.rs:174-:177 twin)
            self.num_counts = 0; // cc:321
            while (self.num_counts as usize) < pegs.len()
                && !pegs[self.num_counts as usize].name.is_empty()
            {
                self.num_counts += 1; // cc:324 `++num_counts`
            }
        }
        let number_of_threads: u32 = if new_thread { 1 } else { instance_max }; // cc:327
        let cols = self.num_counts.max(0) as usize;
        for _ in 0..number_of_threads {
            // cc:329-:334
            self.counts.push(vec![0; cols]);                      // cc:331
            self.dump_stats_counts.push(vec![0; cols]);           // cc:332
            self.dump_stats_initialized.push(0);                  // cc:333
        }
        self.dump_stats_results.resize(cols, 0); // cc:335
    }

    /// module.cc :339-:360 — `p = get_counts(); if ( !p ) return;`
    /// (:341-:344); `pegs = get_pegs(); if ( !pegs ) return;` (:346-:349);
    /// per i < num_counts: counts[get_instance_id()][i] = 0 (:354) +
    /// dump_stats_counts[get_instance_id()][i] = 0 (:355); then `p[i] = 0`
    /// ONLY `if ( pegs[i].type != CountType::NOW )` (:357-:358 — the
    /// NOW-survival face pin `MS reset … p1=5`).
    pub fn reset_stats<V: ModuleVirt + ?Sized>(&mut self, v: &V, p: &mut [PegCount]) {
        if p.is_empty() {
            return; // cc:343-:344 (null-ptr ~ empty model)
        }
        let pegs = match v.get_pegs() {
            Some(q) => q,
            None => return, // cc:348-:349
        };
        let id = v.get_instance_id() as usize; // cc:354/:355
        let n = (self.num_counts.max(0) as usize)
            .min(pegs.len())
            .min(p.len()); // bound-clamp
        for i in 0..n {
            self.counts[id][i] = 0;            // cc:354
            self.dump_stats_counts[id][i] = 0; // cc:355
            if pegs[i].peg_type != CountType::Now {
                p[i] = 0; // cc:357-:358
            }
        }
    }

    /// module.h:157 decl + module.cc :362-:374 — `infos = get_pegs();
    /// assert(infos);` (:364-:365); `for ( unsigned i = 0; infos[i].name;
    /// i++ ) if ( strcmp(peg_name, infos[i].name) == 0 ) return
    /// dump_stats_results[i];` (:367-:370 — the NAME-HIT arm; the consumer
    /// reads dump_stats_results, NOT counts: the SP pin `SP ggc-hit=0`
    /// holds the zero (the SP sum landed 12 in counts, results stayed 0)
    /// while `MS ggc hit=13` reads the aggregated results). THE -DNDEBUG
    /// ARM (harness law, PLAN §9): :372 `assert(false); // wrong name =
    /// programmer error` then :373 `return 0;` — -DNDEBUG (the ground
    /// PRODUCTION arm; the ONLY arm the harness graph builds) makes the
    /// MISS reachable and OBSERVABLE (`miss=0`, vectors MS line); a debug
    /// build of the ground ABORTS. The port models the production arm
    /// unconditionally (cargo cfg != the autotools -DNDEBUG flag, the 18d
    /// DEBUG_MSGS precedent), assert face kept as debug_assert.
    pub fn get_global_count<V: ModuleVirt + ?Sized>(&self, v: &V, peg_name: &str) -> PegCount {
        let infos = v.get_pegs();
        debug_assert!(infos.is_some()); // cc:365 `assert(infos);` (NDEBUG elides)
        if let Some(infos) = infos {
            // cc:367 `for ( unsigned i = 0; infos[i].name; i++ )` — the
            // name-null sentinel stops the walk; C returned dump_stats_
            // results[i] unguarded on the hit (cc:370).
            for (i, info) in infos.iter().take_while(|p| !p.name.is_empty()).enumerate() {
                if peg_name == info.name {
                    // cc:369-:370 strcmp hit -> dump_stats_results[i]
                    // (index-guard: C UB'd on a results table SHORTER than
                    // the peg list — the Rust port returns the 0 the
                    // production miss-arm also yields; panic-free posture)
                    return self.dump_stats_results.get(i).copied().unwrap_or(0);
                }
            }
        }
        // cc:372 `assert(false); // wrong name = programmer error` — the
        // -DNDEBUG production arm ELIDES it (the harness graph builds
        // -DNDEBUG, PLAN §9; a cargo debug build of the ground would abort
        // HERE and the vectors' miss=0 line would never print — the port
        // models the arm the vectors pin, so no debug_assert on this path:
        // the observable is the fall-through itself).
        // cc:373 `return 0;` — the -DNDEBUG OBSERVABLE miss arm (vectors
        // `MS ggc hit=13 miss=0`):
        0
    }

    // ---- the verified trio (module.cc :376-:394; h:211-:214 "Wrappers to
    // check that lists are not tables"). R6-clone law the harness PYPIN
    // re-measures EVERY build: `table_level++` (:378) lands before the
    // guard read `if ( list and table_level < 2 )` (:384) — the state
    // mutation order, NEVER the printf argument order.

    /// module.cc :376-:380 — `table_level++; return begin(fqn, idx, c);`
    pub fn verified_begin<V: ModuleVirt + ?Sized>(&mut self, v: &V, fqn: &str, idx: i32) -> bool {
        self.table_level += 1; // cc:378 (the order face)
        v.begin(fqn, idx)      // cc:379
    }

    /// module.cc :382-:388 — `if ( list and table_level < 2 ) return false;`
    /// (:384-:385) then `return set(fqn, v, c);` (:387 — the Value& param
    /// lands framework::value::Value, the landed 16c carrier). FACE-A pin:
    /// LIST arm at table_level==1 -> `set=0`; TABLE arm -> `set=1`.
    pub fn verified_set<V: ModuleVirt + ?Sized>(
        &mut self,
        v: &V,
        fqn: &str,
        value: &mut Value,
    ) -> bool {
        if self.list && self.table_level < 2 {
            return false; // cc:384-:385 the list guard
        }
        v.set(fqn, value) // cc:387
    }

    /// module.cc :390-:394 — `table_level--; return end(fqn, idx, c);`
    pub fn verified_end<V: ModuleVirt + ?Sized>(&mut self, v: &V, fqn: &str, idx: i32) -> bool {
        self.table_level -= 1; // cc:392
        v.end(fqn, idx)        // cc:393
    }

    // ---- protected count helpers (module.h :236-:267) ----------------
    // each opens `assert(index < num_counts)` (h:238/:247/:262 — NDEBUG
    // elides) then the dump-vs-live store pair.

    /// h:236-:243 `set_peg_count` — dump? dump_stats_counts[id][index] =
    /// value (:240) : counts[id][index] = value (:242).
    pub fn set_peg_count(
        &mut self,
        index: usize,
        value: PegCount,
        dump_stats: bool,
        instance_id: u32,
    ) {
        let id = instance_id as usize;
        debug_assert!((index as i32) < self.num_counts); // h:238
        if dump_stats {
            self.dump_stats_counts[id][index] = value; // h:240
        } else {
            self.counts[id][index] = value; // h:242
        }
    }

    /// h:245-:258 `set_max_peg_count` — the keep-max pair, dump-vs-live
    /// (:250-:251 / :255-:256).
    pub fn set_max_peg_count(
        &mut self,
        index: usize,
        value: PegCount,
        dump_stats: bool,
        instance_id: u32,
    ) {
        let id = instance_id as usize;
        debug_assert!((index as i32) < self.num_counts); // h:247
        if dump_stats {
            // h:248-:252 `if(value > dump_stats_counts[...][index]) … = value`
            if value > self.dump_stats_counts[id][index] {
                self.dump_stats_counts[id][index] = value; // h:251
            }
        } else if value > self.counts[id][index] {
            self.counts[id][index] = value; // h:256
        }
    }

    /// h:260-:267 `add_peg_count` — dump? dump_stats_counts[id][index] +=
    /// value (:264) : counts[id][index] += value (:266).
    pub fn add_peg_count(
        &mut self,
        index: usize,
        value: PegCount,
        dump_stats: bool,
        instance_id: u32,
    ) {
        let id = instance_id as usize;
        debug_assert!((index as i32) < self.num_counts); // h:262
        if dump_stats {
            self.dump_stats_counts[id][index] += value; // h:264
        } else {
            self.counts[id][index] += value; // h:266
        }
    }
}

/// the cc:86 filter face — the NOW-typed indices under the bound clamp
/// (module.o's clear_global_active_counters only touches NOW cells).
fn nows(q: &[PegInfo], n: usize) -> Vec<usize> {
    (0..n).filter(|&i| q[i].peg_type == CountType::Now).collect()
}
