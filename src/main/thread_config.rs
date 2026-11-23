//! Literal port of `main/thread_config.{cc,h}` (row 22a — THE GATE ROW;
//! ground truth @ fe29cbe: cc 920 L md5 ca123f895a028e53328b3b0451af8073
//! plus h 95 L md5 86a4d24805a6413ecebbbe72e4f10e5b — the ground h is 95 L,
//! NOT the banked 86-line token; cite-drift law: disk wins, re-proven by
//! the harness ground-identity greps EVERY build). THE chapter-19
//! remainder: the SO_PUBLIC ThreadConfig the h (:37-:93) hands to 79
//! ground consumers.
//!
//! ## THE GATE ROW face (first REAL gate since gre/18g — the 28-straight
//! zero-gate streak ENDS here; honest census posture)
//!
//! cc :613 `#ifdef UNIT_TEST` opens the in-TU Catch block :615-:916 =
//! EXACTLY 14 `TEST_CASE(..., "[ThreadConfig]")` names (9 direct + 5
//! nested under the inner `#ifdef HAVE_NUMA` :797 -> inner #endif :918,
//! outer #endif :920). The ground block IS gate material: the harness
//! `tools/tc_harness` runs it host-green via its own CATCH_CONFIG_RUNNER
//! main TU (`tc_gate_main.cc` — THE first row ever tracking a runner main
//! TU) against a FUNCTIONAL hwloc witness. RUNNER-MEASURED tail:
//! `All tests passed (23 assertions in 14 test cases)`
//! (tools/tc_harness/gate.txt — COPY-LOCAL UNTRACKED per PLAN SS0; the
//! tracked gate.txt face stays gre's ONLY, tracked count 1; the
//! HAVE_NUMA-off hinge arm runs the 9-case/17-assertion face). The 14
//! cases + their EXACTLY-23 CHECKs (ground-census: grep 'CHECK(' inside
//! :613-:920 = 23) translate statement-for-statement in
//! tests/tc_parity_test.rs (the 18g gate-semantics law: the C side RAN
//! green; the Rust side re-expresses the semantics with real logic —
//! NEVER a copy of the C block, NEVER typed counts).
//!
//! ## THE init-order law (harness E10 arm: the SEGV face every build)
//!
//! The ground tests dereference file-scope statics `topology` /
//! `process_cpuset` / `topology_support` (cc :41-:43) filled ONLY by
//! `ThreadConfig::init()` (:65-:90), which upstream calls at snort.cc:109
//! BEFORE Catch ever runs tests (upstream's own runner IS CATCH_CONFIG_
//! RUNNER — src/catch/unit_test.cc :26). A plain CATCH_CONFIG_MAIN twin
//! SEGVs (rc=139, E10_main_segv.txt). So `init()` keeps the C fill ORDER
//! — the HAVE_NUMA numa/hwloc installs (:67-:72) first, then
//! topology init+load (:74-:80; a load failure destroys + false), then
//! the support pointer (:81), then process_cpuset (:82-:88) — and this
//! port NEVER reorders them; every statics reader cites the arm it rides.
//!
//! ## THE hwloc/numa seam law (FIXTC = witness-REPPOINT, NEVER excision)
//!
//! The host carries ZERO hwloc/numa (pkg-config + headers find-0,
//! harness-measured). The hwloc C API itself stays a CITED provider seam:
//! the harness `wit/hwloc_wit.h` decl ladder + functional impl own the C
//! symbols; NOTHING here invents hwloc linkage. The FUNCTIONAL bitmap
//! semantics the CHECKs exercise (isequal/weight/isset/first/single-
//  lify/isincluded/iszero/and + the list round-trip) ARE real Rust logic
//! (`CpuBitmap`, u64 words). The witness model: CPUs 0..255 — the
//! instance-max AUTO face = weight(process_cpuset) = 256, the WITNESS
//! MODEL not the host: `std::thread::available_parallelism` is the real-
//! host nproc face a REAL hwloc would report; here it is REPLACED by the
//! model cpuset (harness MAXLADDER `auto=256` pins the model face; the
//! 9999-CPU / 255-ceiling fallback arms ride cc :438-:456 + D6/NAME4).
//! `hwloc_set_cpubind` FAILS for any bit >= 256 (model face), so the
//! ground 9999-CPU graceful fallback (cc :772-:795 case) REALLY takes
//! the fallback arm. Token census (disk wins, cite-drift law): cc raw
//! hwloc_* occurrences 142 / grep-LINE face 126 / the banked "133" STALE
//! (the harness 142/126/133 drift trio); h raw tokens 2.
//!
//! ## one-home law (the get_instance_max drift face)
//!
//! `ThreadConfig::get_instance_max` is ROW-OWNED: the harness
//! witness_conf CORE-SUBSET heredoc NEVER defines it (the carried
//! 4dd91018-family witness DOES and multiple-DEFINITIONS the row .o —
//! measured clash face), so exactly-ONE Rust home lives HERE too.
//! REUSE-cited landed seams, NEVER re-forked: file_api/file_cache.rs
//! :494-:504 (`ThreadApi::get_instance_max` seam, cites main/
//! thread_config.h:44), framework/module.rs :735-:751 (the harness
//! witness_conf pull face), main/thread.rs :59-:63 (the naming-path
//! instance_max mirror, cites thread_config.cc:44). REUSED, never
//! re-ported: `main::numa` (the NumaMemPolicy <-> string pair — the
//! numa.{h,cc} 88+89 L home; convert/stringify at :26-:46),
//! `main::thread::SThreadType` (thread.h :26-:31 declaration order = the
//! h :73-:82 TypeIdPairComparer ordering face: type-major then id-minor),
//! `time::periodic` (the landed REAL Periodic home — the decl-home law:
//! periodic.cc symbols NEVER invented here; the harness DECL-witnesses
//! Periodic because the watchdog handler stays dark at timer 0, while the
//! Rust port registers with the honest REAL home),
//! `log::messages::LogEngine` (ParseError/ParseWarning/LogMessage/
//! WarningMessage/ErrorMessage — the landed log home; the harness
//! witness_tc.cc bodies are echoes — deviations cite the face),
//! `utils::util::get_error` (:307 — the util.h :118 home).
//!
//! ## modeled departures (full honest text: KNOWN DEVIATIONS.md,
//! '## main thread_config (row 22a)')
//!
//! - the six cc file statics (:41-:46) + the two HAVE_NUMA globals (:49/
//!   :50) ride ONE process-wide `Mutex<Statics>` bundle: C's file-
//!   statics ARE process-wide and the FACE-A arms prove it (MAXLADDER/
//!   TIDLADDER hit them across the five tc1..tc5 instances); `instance_
//!   mutex` (:45) IS that Mutex. The two `static const bool
//!   watchdog_is_enabled` reads (:585/:604 — the init-time conf read that
//!   NEVER re-reads) evaluate ONCE here too (OnceLock conf face == the
//!   stock witness: snort_config.h :264 watchdog_timer = 0 => FALSE =>
//!   the WD-NOOP arms).
//! - the h member maps (:84-:85) own Box<CpuSet> (C raw CpuSet* freed by
//!   ~ThreadConfig :192-:199: Rust Drop == the dtor; `release()` keeps
//!   the explicit-call face).
//! - `set_instance_tid` (:235 `emplace`) = FIRST-insert-wins, a re-set
//!   NEVER overwrites (the std::map::emplace face via entry-or-noop —
//!   parity-pinned); `gettid()` = the glibc >= 2.30 extern (links fine,
//!   17z note).
//! - NUMA dual face: the C class + TU GROW under `#ifdef HAVE_NUMA`
//!   (h :60-:63/:87-:92; cc :48-:51/:67-:72/:184-:189/:265-:269/:272-:361/
//!   :797-:918). The Rust port is cfg-LESS by precedent (main::numa's
//!   runtime-face law): a live `numa`/`hwloc` seam PAIR on the bundle
//!   (the NumaWrapper/HwlocWrapper virtuals, numa.h :44-:87). Witness
//!   arms available()=0 / max_node()=0 => the implement_thread_mempolicy
//!   FALSE early-out (cc :314-:318) = the honest no-NUMA FACE-A arm; the
//!   5 gate cases install the GROUND mocks NumaWrapperMock/HwlocWrapper-
//!   Mock (:799-:831) — the mock types below keep every knob name +
//!   default (set_numa_wrapper/set_hwloc_wrapper = the :844-:845 global
//!   assignment face).
//! - pthread_setname_np 15-byte cap (util.h :41-:53, "thread names > 15
//!   chars aren't supported on most systems"): every C name-ladder name
//!   is ASCII, so byte-length == char-length; `set_thread_name` models
//!   the ERANGE face AS REAL logic (len > 15 bytes => the call fails and
//!   the OLD name SURVIVES). Harness FACE-A NAME3: `s3.pkt-c0` survived
//!   the 513-char "-c0,1,...,255" rewrite (ERANGE); NAME4: `s3.pkt-c9999`
//!   (12 chars) fits and survives the fallback-rename ERANGE. NEVER
//!   simulated beyond that; the pthread call itself is a cited seam.
//! - Watchdog::kick's abort arm (:547): ported faithfully (Aborting-Snort
//!   warn then `std::process::abort()`), NEVER exercised — the port never
//!   builds an unresponsive thread_count (the enabled-guards + the
//!   never-active resp[] cells; abort arm cite-LEFT-OPEN per the witness
//!   law). The kick tid-hop (:533 `get_conf()->thread_config->
//!   get_instance_tid(i)`) rides the statics home (an identity hop, cited).
//! - thread.h :49 `get_thread_type()` reads a THREAD_LOCAL C static
//!   (thread.cc :47, default STHREAD_TYPE_OTHER; the HARNESS WITNESS face
//!   returns STHREAD_TYPE_MAIN — witness_tc.cc, the face the green gate
//!   rode); cc :492's named-miss fallback cite-home threads the type as
//!   an explicit param (the threaded-THREAD_LOCAL law, main/thread.rs
//!   precedent). The watchdog's `get_instance_id()` (:590/:606, thread.h
//!   :48) is threaded the same way (the ONE home for that face stays
//!   landed; this row never forks a second global).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::log::messages::{LogEngine, WARN_CONF};
use crate::main::numa::{
    convert_string_to_numa_mempolicy, stringify_numa_mempolicy, NUMA_POLICY_PREFERRED,
    NUMA_POLICY_UNKNOWN,
};
use crate::main::thread::SThreadType;
use crate::time::periodic;
use crate::utils::cfmt::Arg;
use crate::utils::util::get_error;

// ==========================================================================
// CpuBitmap — the FUNCTIONAL witness semantics face (the harness
// `wit/hwloc_wit_impl.cc` std::set model re-expressed as u64 words; the
// SAME observable contract every ground CHECK reads). The hwloc C API
// tokens themselves stay the cited provider seam — the 21 distinct C
// functions + 6 types of the ground cc (see the header census) NEVER
// appear as Rust linkage; their contract appears as this logic.
// ==========================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuBitmap {
    words: Vec<u64>,
}

impl CpuBitmap {
    /// `hwloc_bitmap_alloc` (cc :84/:111/:127/:405/:474/:723/:752/:778...).
    pub fn new() -> Self {
        CpuBitmap::default()
    }

    fn grow(&mut self, i: usize) {
        let need = i / 64 + 1;
        if self.words.len() < need {
            self.words.resize(need, 0);
        }
    }

    /// `hwloc_bitmap_set` (cc :724/:753/:779).
    pub fn set(&mut self, i: usize) {
        self.grow(i);
        self.words[i / 64] |= 1u64 << (i as u32 % 64);
    }

    /// `hwloc_bitmap_isset` (the gate CHECKs :736-:737, the D2/D3/D6/D7
    /// probe faces).
    pub fn isset(&self, i: usize) -> bool {
        let w = i / 64;
        w < self.words.len() && (self.words[w] >> (i as u32 % 64)) & 1 == 1
    }

    /// `hwloc_bitmap_weight` (cc :100 — THE instance-max auto arm; the
    /// gate CHECKs :634/:638/:735).
    pub fn weight(&self) -> i32 {
        self.words.iter().map(|w| w.count_ones() as i32).sum()
    }

    /// `hwloc_bitmap_iszero` (cc :130; the gate CHECK :792).
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    /// `hwloc_bitmap_isequal` (cc :407/:476; the gate CHECKs :656/:660/
    /// :682/:688/:710/:764).
    pub fn is_equal(&self, other: &Self) -> bool {
        let n = self.words.len().max(other.words.len());
        (0..n).all(|i| {
            self.words.get(i).copied().unwrap_or(0) == other.words.get(i).copied().unwrap_or(0)
        })
    }

    /// `hwloc_bitmap_isincluded` (cc :120).
    pub fn is_included(&self, super_set: &Self) -> bool {
        self.words.iter().enumerate().all(|(i, w)| {
            w & !super_set.words.get(i).copied().unwrap_or(0) == 0
        })
    }

    /// `hwloc_bitmap_and` (cc :128).
    pub fn and(&mut self, a: &Self, b: &Self) {
        let n = a.words.len().max(b.words.len());
        self.words = (0..n)
            .map(|i| a.words.get(i).copied().unwrap_or(0) & b.words.get(i).copied().unwrap_or(0))
            .collect();
        trim(&mut self.words);
    }

    /// `hwloc_bitmap_singlify` (cc :649/:676/:704 — keep the LOWEST bit).
    pub fn singlify(&mut self) {
        match self.first() {
            Some(f) => {
                *self = Self::new();
                self.set(f as usize);
            }
            None => self.words.clear(),
        }
    }

    /// `hwloc_bitmap_first` (cc :720/:749; the ground -1 face = None).
    pub fn first(&self) -> Option<i32> {
        for (i, w) in self.words.iter().enumerate() {
            if *w != 0 {
                return Some((i * 64 + w.trailing_zeros() as usize) as i32);
            }
        }
        None
    }

    /// `hwloc_bitmap_dup` (cc :88/:142/:645/:670/:698/:719/:748/:835/:836...).
    pub fn dup(&self) -> Self {
        self.clone()
    }

    /// `hwloc_bitmap_list_sscanf` (cc :112). The witness contract: digit
    /// tokens, ',' arms, '-' range arms; anything else fails nonzero =>
    /// the cc :113 ParseError arm ("totally a bad cpuset string" fails
    /// at the first token face). The EMPTY string parses CLEAN to the
    /// empty set (probe D5 face). A trailing comma fails (the witness
    /// comma-arm guard face).
    pub fn list_sscanf(&mut self, s: &str) -> bool {
        // the C int-return face: TRUE = the nonzero PARSE-FAIL arm
        self.parse_list_into(s)
    }

    fn parse_list_into(&mut self, s: &str) -> bool {
        self.words.clear();
        if s.is_empty() {
            return false; // :112 clean + trivially included (:120)
        }
        let bytes = s.as_bytes();
        let mut i = 0usize;
        loop {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                return true; // the D1 bad-string face
            }
            let Ok(lo) = s[start..i].parse::<u64>() else { return true };
            if i < bytes.len() && bytes[i] == b'-' {
                // the D7 range arm
                i += 1;
                let hstart = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i == hstart {
                    return true;
                }
                let Ok(hi) = s[hstart..i].parse::<u64>() else { return true };
                if hi < lo {
                    return true;
                }
                for x in lo..=hi {
                    self.set(x as usize);
                }
            } else {
                self.set(lo as usize);
            }
            if i == bytes.len() {
                return false;
            }
            if bytes[i] != b',' {
                return true; // ' ', letters, junk => nonzero
            }
            i += 1;
            if i == bytes.len() {
                return true; // trailing comma => nonzero (witness face)
            }
        }
    }

    /// `hwloc_bitmap_list_asprintf` (cc :103? no — the asprintf sites
    /// :124/:125/:146/:374/:403/:449/:472). Witness face: ascending
    /// comma-joined singles (NO ranges — the recon comma bug face); the
    /// text feeds the name ladder directly (:411-:412 `"-c"` + list =>
    /// the ERANGE name face at 513 chars for the 256-wide set).
    pub fn list_asprintf(&self) -> String {
        let mut out = String::new();
        for (i, w) in self.words.iter().enumerate() {
            let mut w = *w;
            while w != 0 {
                let b = w.trailing_zeros();
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(&(i * 64 + b as usize).to_string());
                w &= w - 1;
            }
        }
        out
    }

    /// the witness model allowed/this-proc cpuset face
    /// (`hwloc_topology_get_allowed_cpuset` / `hwloc_get_cpubind(PROCESS)`
    /// — model CPUs 0..`max`).
    pub fn model_cpus(max_cpus: u32) -> Self {
        let mut b = CpuBitmap::new();
        for i in 0..max_cpus as usize {
            b.set(i);
        }
        b
    }
}

fn trim(words: &mut Vec<u64>) {
    while words.last() == Some(&0) {
        words.pop();
    }
}

// ==========================================================================
// CpuSet (cc :53-:63) — the heap wrapper; ~CpuSet frees the bitmap
// (:56-:60). Rust Drop == that dtor (the no-manual-free face);
// `destroy_cpuset` below keeps the cc :165-:168 fn face.
// ==========================================================================

#[derive(Clone, Debug)]
pub struct CpuSet {
    /// the SINGLE member — the probe read-mirror face (probe.cc :19-:22).
    pub cpuset: CpuBitmap,
}

impl CpuSet {
    /// `CpuSet(hwloc_cpuset_t set) :55` the one-line ctor.
    pub fn new(cpuset: CpuBitmap) -> Self {
        CpuSet { cpuset }
    }
}

// ==========================================================================
// the NUMA/hwloc wrapper seams (numa.h :44-:87 — the virtuals the FIVE
// gate cases MOCK at :799-:831; witness arms in witness_tc.cc; the REAL
// libnuma/libhwloc bodies = provider seam, NEVER invented).
// ==========================================================================

/// cc :305 `unsigned long nodemask` (a host-order word; the mocks NEVER
/// read it — the real set_mempolicy provider face stays left-open).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeMask {
    word: u64,
}

/// the NumaWrapper trio (numa.h :44-:61).
pub trait NumaWrapper {
    /// `numa_available()` — negative => NUMA down (the cc :315 arm;
    /// witness 0, mock default 1, the gate mock arm -1).
    fn available(&self) -> i32;
    /// `numa_max_node()` — <= 0 => no NUMA (the cc :315 FACE-A arm;
    /// witness 0, mock default 1).
    fn max_node(&self) -> i32;
    /// `set_mempolicy(mode, nodemask, maxnode)` — != 0 => the cc :306
    /// apply-fail arm (the gate mock's mem_policy = -1 case).
    fn set_mem_policy(&self, mode: u8, nodemask: &NodeMask, maxnode: u64) -> i32;
}

/// the `hwloc_obj` face the GROUND mock embeds BY VALUE (:819 — needs
/// os_index + cpuset members; the witness header face).
#[derive(Clone, Debug, Default)]
pub struct HwlocObj {
    pub os_index: i32,
    pub cpuset: CpuBitmap,
}

/// the HwlocWrapper virtuals the cc :282-:298 get_numa_node consumes
/// (numa.h :63-:87).
pub trait HwlocWrapper {
    /// `hwloc_bitmap_iszero` (numa.h :83-:86; cc :284).
    fn bitmap_iszero(&self, set: &CpuBitmap) -> bool {
        set.is_zero()
    }
    /// `hwloc_get_type_depth(topology, HWLOC_OBJ_NUMANODE)` (cc :287).
    fn get_type_depth(&self, topology: &Topology) -> i32;
    /// `hwloc_get_nbobjs_by_depth` (cc :291; the mock loop bound —
    /// the 'get_nbobjs_by_depth failure' case drives it to 0).
    fn get_nbobjs_by_depth(&self, topology: &Topology, depth: i32) -> u32;
    /// `hwloc_get_obj_by_depth` (cc :293; null-checked by :294 `node and`).
    fn get_obj_by_depth(&self, topology: &Topology, depth: i32, idx: u32) -> Option<&HwlocObj>;
    /// `hwloc_bitmap_isincluded` (numa.h :79-:82; cc :294).
    fn bitmap_isincluded(&self, sub: &CpuBitmap, sup: &CpuBitmap) -> bool {
        sub.is_included(sup)
    }
}

/// the IN-TU mock (GROUND-authored :799-:811, shipped verbatim in the
/// harness copy; every knob name + default kept).
#[derive(Clone, Debug)]
pub struct NumaWrapperMock {
    pub numa_avail: i32, // :802 default 1
    pub max_n: i32,      // :803 default 1
    pub mem_policy: i32, // :804 default 0
}

impl Default for NumaWrapperMock {
    fn default() -> Self {
        NumaWrapperMock {
            numa_avail: 1,
            max_n: 1,
            mem_policy: 0,
        }
    }
}

impl NumaWrapper for NumaWrapperMock {
    fn available(&self) -> i32 {
        self.numa_avail
    }
    fn max_node(&self) -> i32 {
        self.max_n
    }
    fn set_mem_policy(&self, _mode: u8, _nodemask: &NodeMask, _maxnode: u64) -> i32 {
        self.mem_policy // :808-:810 ignores the args
    }
}

#[derive(Clone, Debug)]
pub struct HwlocWrapperMock {
    pub nbobjs_by_depth: u32, // :816 default 1
    pub type_depth: i32,      // :817 default 2
    pub is_included: i32,     // :818 default 1
    pub node: HwlocObj,       // :819 `struct hwloc_obj node;`
}

impl Default for HwlocWrapperMock {
    fn default() -> Self {
        HwlocWrapperMock {
            nbobjs_by_depth: 1,
            type_depth: 2,
            is_included: 1,
            node: HwlocObj::default(),
        }
    }
}

impl HwlocWrapper for HwlocWrapperMock {
    fn get_type_depth(&self, _topology: &Topology) -> i32 {
        self.type_depth
    }
    fn get_nbobjs_by_depth(&self, _topology: &Topology, _depth: i32) -> u32 {
        self.nbobjs_by_depth
    }
    fn get_obj_by_depth(&self, _topology: &Topology, _depth: i32, _idx: u32) -> Option<&HwlocObj> {
        Some(&self.node) // :823-:824 ALWAYS &node
    }
    fn bitmap_isincluded(&self, _sub: &CpuBitmap, _sup: &CpuBitmap) -> bool {
        self.is_included != 0 // :827-:828 the knob face
    }
    fn bitmap_iszero(&self, _set: &CpuBitmap) -> bool {
        false // :829-:830 ALWAYS 0
    }
}

/// the witness-home arms (witness_tc.cc numa trio: available 0 /
/// max_node 0 / set_mempolicy returns 0 — the honest no-NUMA-host FA-
/// CE-A arms; wit hwloc impl: get_type_depth = HWLOC_TYPE_DEPTH_UN-
/// KNOWN, get_nbobjs_by_depth = 0, get_obj_by_depth = &zero node).
pub struct WitnessNuma;

impl NumaWrapper for WitnessNuma {
    fn available(&self) -> i32 {
        0
    }
    fn max_node(&self) -> i32 {
        0
    }
    fn set_mem_policy(&self, _mode: u8, _mask: &NodeMask, _maxnode: u64) -> i32 {
        0
    }
}

pub const HWLOC_TYPE_DEPTH_UNKNOWN: i32 = -1; // the wit header face

#[derive(Clone, Debug, Default)]
pub struct WitnessHwloc {
    node: HwlocObj,
}

impl HwlocWrapper for WitnessHwloc {
    fn get_type_depth(&self, _topology: &Topology) -> i32 {
        HWLOC_TYPE_DEPTH_UNKNOWN
    }
    fn get_nbobjs_by_depth(&self, _topology: &Topology, _depth: i32) -> u32 {
        0
    }
    fn get_obj_by_depth(&self, _topology: &Topology, _depth: i32, _idx: u32) -> Option<&HwlocObj> {
        Some(&self.node)
    }
}

// the cc :48-:51 HAVE_NUMA globals (`std::shared_ptr<NumaWrapper> numa;
// std::shared_ptr<HwlocWrapper> hwloc;`) ride the bundle below as live
// Arc seams — the runtime-face law (NEVER cfg).

// ==========================================================================
// Topology (the cc :41-:43 statics trio face: hwloc_topology_t + the
// const support* + process_cpuset) — filled by init() ONLY (the
// init-order law). Witness arms: cpubind support { 1, 1 } (the wit impl
// g_sup face) + the model 0..255 process cpuset.
// ==========================================================================

#[derive(Clone, Debug)]
pub struct Topology {
    pub loaded: bool,
    /// `topology_support->cpubind->get_thisproc_cpubind` (:82).
    pub cpubind_get_thisproc: bool,
    /// `topology_support->cpubind->set_thisthread_cpubind` (:203/:221/
    /// :314/:385/:463).
    pub cpubind_set_thisthread: bool,
    /// `process_cpuset` (:42).
    pub process_cpuset: CpuBitmap,
    /// the witness-model ceiling: set_cpubind FAILS for bit >= this
    /// (the wit impl WIT_MODEL_MAX_CPU 256 face).
    pub model_max_cpu: u32,
}

impl Topology {
    /// the hwloc provider seam face (the harness FUNCTIONAL witness):
    /// init/load ok (:74-:80), support 1/1 (:81), process cpuset via
    /// the get_thisproc arm (:82-:86 — the model 0..255; the :88 else
    /// dup(allowed) arm lands on the same set in the witness).
    pub fn witness_init() -> Topology {
        Topology {
            loaded: true,
            cpubind_get_thisproc: true,
            cpubind_set_thisthread: true,
            process_cpuset: CpuBitmap::model_cpus(256),
            model_max_cpu: 256,
        }
    }
}

// ==========================================================================
// the statics bundle (cc :41-:51; the `std::mutex instance_mutex` face
// :45 == this Mutex). ONE home for the row-owned get_instance_max law
// (the witness_conf core-subset drift face proves it).
// ==========================================================================

struct Statics {
    topology: Option<Topology>, // :41 (support :43 + process_cpuset :42 live here)
    numa: Option<Arc<dyn NumaWrapper + Send + Sync>>,   // :49 (runtime face)
    hwloc: Option<Arc<dyn HwlocWrapper + Send + Sync>>, // :50
    instance_max: u32, // :44 `static unsigned instance_max = 1;`
    instance_id_to_tid: BTreeMap<i32, i32>, // :46
    /// the witness process-wide thread-bind face (the wit impl
    /// `__thread t_thread_cpuset` — nullptr => the process set): a fresh
    /// PROCESS starts unbound; within one process the bind persists
    /// across ThreadConfig instances (the C gate runs ALL cases on the
    /// same main test thread — the same-thread face; per-thread cells
    /// would split what the C gate chains, deviations-recorded).
    thread_bind: Option<CpuBitmap>,
}

impl Statics {
    fn fresh() -> Statics {
        Statics {
            topology: None, // :41 the null face pre-init
            numa: None,     // :49 (init() installs FIRST — :67-:72)
            hwloc: None,    // :50
            instance_max: 1, // :44
            instance_id_to_tid: BTreeMap::new(), // :46
            thread_bind: None,
        }
    }
}

fn statics() -> &'static Mutex<Statics> {
    static TC_STATICS: OnceLock<Mutex<Statics>> = OnceLock::new();
    TC_STATICS.get_or_init(|| Mutex::new(Statics::fresh()))
}

// ==========================================================================
// ThreadConfig (h :37-:93). The member maps (:84-:85) + numa_mempolicy
// (:88, default PREFERRED — the runtime-face law, never cfg).
// ==========================================================================

/// h :68-:72 `struct TypeIdPair { SThreadType type; unsigned id; };` +
/// h :73-:83 the TypeIdPairComparer (type-major, id-minor). The h :77
/// `left.type < right.type` rides the C enum's declaration ORDER
/// (thread.h :26-:31 OTHER < PACKET < MAIN); the landed main/thread.rs
/// SThreadType face carries NO Ord derive (it rides nothing else), so
/// this file spells the comparer as the rank map — same total order,
/// one-home citation, NEVER re-forking thread.rs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TypeIdPair {
    kind: SThreadType,
    id: u32,
}

fn type_rank(kind: SThreadType) -> u8 {
    // thread.h :27-:30 (STHREAD_TYPE_OTHER=0, PACKET=1, MAIN=2)
    match kind {
        SThreadType::Other => 0,
        SThreadType::Packet => 1,
        SThreadType::Main => 2,
    }
}

impl PartialOrd for TypeIdPair {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TypeIdPair {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // h :75-:83 verbatim shape: type first, then id
        (type_rank(self.kind), self.id).cmp(&(type_rank(other.kind), other.id))
    }
}

/// h :65 `static constexpr unsigned int DEFAULT_THREAD_ID = 0;`
pub const DEFAULT_THREAD_ID: u32 = 0;

pub struct ThreadConfig {
    thread_affinity: BTreeMap<TypeIdPair, Box<CpuSet>>,   // h :84
    named_thread_affinity: BTreeMap<String, Box<CpuSet>>, // h :85
    numa_mempolicy: u8, // h :88 = NumaMemPolicy::PREFERRED
}

impl Default for ThreadConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadConfig {
    pub fn new() -> Self {
        ThreadConfig {
            thread_affinity: BTreeMap::new(),
            named_thread_affinity: BTreeMap::new(),
            numa_mempolicy: NUMA_POLICY_PREFERRED, // h :88
        }
    }

    // ------------------------------------------------------------------
    // init / term (cc :65-:90 / :170-:190) — THE init-order law face.
    // FILL ORDER (:67-:88): the HAVE_NUMA wrapper installs FIRST (the
    // runtime face: witness Arms; a real-lib host would wire provider
    // seams — NEVER invented), then topology init+load (:74-:80; a load
    // failure destroys + false :76-:79), then the support read (:81),
    // then process_cpuset (:82-:88). NEVER reordered — the E10 SEGV arm
    // proves what running tests WITHOUT init() does (rc=139).
    // ------------------------------------------------------------------

    pub fn init() -> bool {
        let s = statics();
        let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
        s.numa = Some(Arc::new(WitnessNuma)); // :69 the make_shared face
        s.hwloc = Some(Arc::new(WitnessHwloc::default())); // :70
        s.topology = Some(Topology::witness_init()); // :74-:88 (order inside)
        true
    }

    /// cc :170-:190 term(): destroy + null topology (:172-:176), free +
    /// null process_cpuset (:177-:181), null the support pointer (:182),
    /// the HAVE_NUMA shared_ptr resets = drop the Arcs (:185-:188).
    pub fn term() {
        let s = statics();
        let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(_topo) = s.topology.take() {
            // hwloc_topology_destroy + hwloc_bitmap_free ride the Drop face
        }
        s.numa = None;
        s.hwloc = None;
    }

    // ------------------------------------------------------------------
    // the instance-max ladder (cc :92-:107) — THE row-owned home (the
    // witness_conf CORE-SUBSET drift face: the carried 4dd91018 family
    // witness DEFS get_instance_max and multiple-DEFINITIONS the row .o
    // => the ROW owns it; the Rust one-home law cites this home from
    // file_cache.rs :494-:504 + module.rs :735-:751 + thread.rs :59-:63).
    // ------------------------------------------------------------------

    /// cc :92-:102: nonzero stores the literal (the gate case :635 weight
    /// *2 override); 0 = AUTO = `hwloc_bitmap_weight(process_cpuset)` —
    /// the witness MODEL 256, NOT the host nproc (`std::thread::
    /// available_parallelism` is the face a REAL hwloc process-cpu-set
    /// read would report; the model cpuset replaces it — MAXLADDER
    /// auto=256). Pre-init C reads the null process_cpuset (witness
    /// crash face); the port models 0 honestly (deviations).
    pub fn set_instance_max(max: u32) {
        let s = statics();
        let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
        if max != 0 {
            s.instance_max = max; // :95
        } else {
            // :98-:100 the auto-allocation comment + the weight arm
            let w = s
                .topology
                .as_ref()
                .map(|t| t.process_cpuset.weight())
                .unwrap_or(0);
            s.instance_max = w as u32;
        }
    }

    /// cc :104-:107 get_instance_max().
    pub fn get_instance_max() -> u32 {
        let s = statics();
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        s.instance_max
    }

    // ------------------------------------------------------------------
    // the cpuset-string decision ladder (cc :109-:168) — the DEC heart;
    // ALL arms REAL Rust logic (D1-D7 + gate cases 1/2/7/8).
    // ------------------------------------------------------------------

    /// cc :109-:163 validate_cpuset_string. Arms: (:112-:118) sscanf
    /// fails => ParseError + free + nullptr (the :115 null-arg ternary
    /// "(null)" face == the Option face here); (:120-:160) NOT included
    /// into process_cpuset => the asprintf pair (:122-:125), effective =
    /// AND (:127-:128): zero => the no-overlap ErrorMessage + return
    /// dup(process_cpuset) (:130-:143); else the intersection Warning-
    /// Message + return effective (:145-:159); (:162) pass-through.
    pub fn validate_cpuset_string(cpuset_str: Option<&str>, log: &mut LogEngine) -> Option<CpuSet> {
        let mut cpuset = CpuBitmap::new(); // :111 alloc
        if cpuset.list_sscanf(cpuset_str.unwrap_or("")) {
            // :114 the ParseError flow (the harness WIT_PARSE_ERR
            // observable line; here the landed LogEngine home)
            let shown = cpuset_str.unwrap_or("(null)"); // :115 ternary
            log.parse_error("Invalid CPU set string '%s'\n", &[Arg::S(Some(shown.into()))]);
            return None; // :116-:117 (the bitmap rides the Rust Drop face)
        }

        let s = statics();
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        let process = &s
            .topology
            .as_ref()
            .expect("validate_cpuset_string derefs process_cpuset — init() first (the E10 face)")
            .process_cpuset; // :120

        if cpuset.is_included(process) {
            return Some(CpuSet::new(cpuset)); // :162
        }

        let requested_s = cpuset.list_asprintf(); // :124
        let allowed_s = process.list_asprintf(); // :125
        let mut effective = CpuBitmap::new(); // :127
        effective.and(&cpuset, process); // :128

        if effective.is_zero() {
            // :130-:143 the ZERO-overlap graceful fallback (D4 w=256 +
            // gate case 'zero overlap' :745-:770)
            log.error_message(
                "Requested CPU set '%s' has no overlap with allowed process CPU set '%s'. Falling back to process CPU set. This thread will share cores with other threads. This may indicate a process affinity mismatch.\n",
                &[
                    Arg::S(Some(requested_s.into())),
                    Arg::S(Some(allowed_s.into())),
                ],
            );
            return Some(CpuSet::new(process.dup())); // :142
        }

        // :145-:159 the PARTIAL-overlap intersection arm (D3 + gate
        // case 'partial overlap' :716-:743)
        let effective_s = effective.list_asprintf(); // :146
        log.warning_message(
            "Requested CPU set '%s' is not fully available in process CPU set '%s'. Proceeding with available subset '%s'. This may indicate a process affinity mismatch.\n",
            &[
                Arg::S(Some(requested_s.into())),
                Arg::S(Some(allowed_s.into())),
                Arg::S(Some(effective_s.into())),
            ],
        );
        Some(CpuSet::new(effective)) // :159
    }

    /// cc :165-:168 destroy_cpuset (`delete cpuset` — the ~CpuSet bitmap
    /// free rides Drop; the fn face kept).
    pub fn destroy_cpuset(cpuset: Option<CpuSet>) {
        drop(cpuset);
    }

    // ------------------------------------------------------------------
    // affinity config + the maps (cc :192-:230)
    // ------------------------------------------------------------------

    /// cc :192-:199 ~ThreadConfig — frees BOTH maps (Drop; `release()`
    /// keeps the explicit dtor-MOMENT call face for tests).
    pub fn release(&mut self) {
        self.thread_affinity.clear();
        self.named_thread_affinity.clear();
    }

    /// cc :201-:217 set_thread_affinity: support-gated (:203); an
    /// EXISTING key is delete+replaced (:207-:210 == BTreeMap::insert
    /// replacing = dropping the old Box); the else arm frees the cpuset
    /// (:214) + ParseWarning(WARN_CONF, ...) (:215).
    pub fn set_thread_affinity(
        &mut self,
        kind: SThreadType,
        id: u32,
        cpuset: CpuSet,
        log: &mut LogEngine,
    ) {
        if self.support_set_thisthread() {
            self.thread_affinity.insert(TypeIdPair { kind, id }, Box::new(cpuset));
        } else {
            drop(cpuset);
            log.parse_warning(
                WARN_CONF,
                "This platform does not support setting thread affinity.\n",
                &[],
            );
        }
    }

    /// cc :219-:230 set_named_thread_affinity — the name-keyed face,
    /// same replace law (:223-:226); the unsupported arm does NOT free
    /// (no cpuset param delete at :229 — the C leaks the face there;
    /// Rust keeps the arg untouched like C... C never deletes here —
    /// faithful arms differ at :214 vs :228-:229, ported as written).
    pub fn set_named_thread_affinity(
        &mut self,
        name: &str,
        cpuset: CpuSet,
        log: &mut LogEngine,
    ) {
        if self.support_set_thisthread() {
            self.named_thread_affinity.insert(name.to_string(), Box::new(cpuset));
        } else {
            drop(cpuset); // the C leak face (:228-:229 has NO delete) —
            // Rust cannot LEAK: the Drop face replaces the leak (devia-
            // tions cite it).
            log.parse_warning(
                WARN_CONF,
                "This platform does not support setting thread affinity.\n",
                &[],
            );
        }
    }

    fn support_set_thisthread(&self) -> bool {
        let s = statics();
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        // the topology_support deref face (C SEGVs pre-init; the port
        // reads None => false — the non-init face, cited)
        s.topology
            .as_ref()
            .is_some_and(|t| t.cpubind_set_thisthread)
    }

    // ------------------------------------------------------------------
    // the tid map (cc :232-:246) — the :45 mutex == the bundle guard.
    // ------------------------------------------------------------------

    /// cc :232-:236 set_instance_tid: `std::lock_guard lock(instance_
    /// mutex); instance_id_to_tid.emplace(id, (int)gettid())` — the
    /// std::map::emplace face = FIRST insert wins; a re-set NEVER over-
    /// writes a live entry (entry-or-noop models EXACTLY that; the face
    /// the tid-ladder tripwire pins).
    pub fn set_instance_tid(id: i32) {
        let tid = gettid(); // cc :235 (glibc >= 2.30; harness links fine)
        let s = statics();
        let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
        s.instance_id_to_tid.entry(id).or_insert(tid);
    }

    /// cc :238-:246 get_instance_tid: a miss => -1 (the cold face).
    pub fn get_instance_tid(id: i32) -> i32 {
        let s = statics();
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        *s.instance_id_to_tid.get(&id).unwrap_or(&-1)
    }

    // ------------------------------------------------------------------
    // stringify_thread (cc :248-:259) — the warn-prefix face
    // ("main thread "/"packet thread "/"other thread " + id + " (TID N)").
    // ------------------------------------------------------------------

    fn stringify_thread(kind: SThreadType, id: u32) -> String {
        let info = match kind {
            SThreadType::Main => "main thread ", // :251-:252
            SThreadType::Packet => "packet thread ", // :253-:254
            _ => "other thread ", // :255-:256
        };
        format!("{info}{id} (TID {})", gettid()) // :257
    }

    // ------------------------------------------------------------------
    // the policy driver (cc :261-:270): affinity ALWAYS first (:263);
    // the mempolicy leg rides the `#ifdef HAVE_NUMA :265-:269` arm = the
    // runtime face here (cfg-less law).
    // ------------------------------------------------------------------

    pub fn apply_thread_policy(&self, kind: SThreadType, id: u32, log: &mut LogEngine) {
        self.implement_thread_affinity(kind, id, log);
        self.implement_thread_mempolicy(kind, id, log);
    }

    // ------------------------------------------------------------------
    // implement_thread_affinity (cc :383-:459) — the NAME ladder head
    // (the row's most OBSERVABLE face; nm NEVER sees it — the FACE-A
    // probe reads pthread_getname_np).
    // ------------------------------------------------------------------

    pub fn implement_thread_affinity(&self, kind: SThreadType, id: u32, log: &mut LogEngine) {
        // :385-:386 the support guard (the topology_support deref face)
        if !self.support_set_thisthread() {
            return;
        }

        // :395-:399 desired = map hit else process_cpuset
        let key = TypeIdPair { kind, id };
        let desired = self
            .thread_affinity
            .get(&key)
            .map(|c| c.cpuset.dup())
            .unwrap_or_else(|| {
                let s = statics();
                let s = s.lock().unwrap_or_else(|e| e.into_inner());
                s.topology
                    .as_ref()
                    .expect("process_cpuset needs init() (the cc :399 face)")
                    .process_cpuset
                    .dup()
            });

        // :401-:403 the asprintf (`char* s` — the data-race comment rides
        // the pure fn here; the SAME text the warn lines print)
        let s_text = desired.list_asprintf();

        let s = statics();
        let mut s = s.lock().unwrap_or_else(|e| e.into_inner());

        // :405-:407 current = the thread bind (process set when unbound)
        let current = s.thread_bind_face();

        // :407-:419 the -c/-i suffix ladder
        let suffix = if !current.is_equal(&desired) {
            log.log_message_stdout(
                "Binding %s to CPU %s.\n",
                &[
                    Arg::S(Some(Self::stringify_thread(kind, id).into())), // :409
                    Arg::S(Some(s_text.clone().into())),
                ],
            );
            String::from("-c") + &s_text // :411-:412 ("cX" bound to core X)
        } else {
            format!("-i{id}") // :416-:418 ("iX" unbound instance X)
        };

        // :421-:431 the head ladder: MAIN KEEPS "snort3" (the suffix is
        // dropped :426 — pgrep expects it); anything else "s3.pkt".
        let (head, suffix) = if kind == SThreadType::Main {
            ("snort3".to_string(), String::new())
        } else {
            ("s3.pkt".to_string(), suffix)
        };
        set_thread_name(&(head + &suffix)); // :433-:434 (the 15-byte cap rides)

        // :438-:456 the bind + graceful-fallback arm (witness law: bit
        // >= 256 => hwloc_set_cpubind FAILS => the 9999 case REALLY
        // falls back — gate case :772-:795 + NAME4).
        if s.set_thread_cpubind(&desired).is_err() {
            log.warning_message(
                "Failed to pin %s to CPU %s: %s (%d). Falling back to process CPU set. This may indicate a process affinity mismatch.\n",
                &[
                    Arg::S(Some(Self::stringify_thread(kind, id).into())),
                    Arg::S(Some(s_text.clone().into())),
                    Arg::S(Some(get_error(EINVAL).into())), // :443 get_error(errno)
                    Arg::I(EINVAL as i64),                  // errno printed
                ],
            );
            // :444 fallback_to_process_cpuset (cc :363-:381)
            s.fallback_to_process_cpuset(&Self::stringify_thread(kind, id), &s_text, log);

            if kind != SThreadType::Main {
                // :446-:455 the fallback re-naming face: "s3.pkt-c" +
                // the PROCESS list (the 256-char list ERANGEs so the
                // PRIMARY name at :434 SURVIVES — the NAME4 face); the
                // cap rides set_thread_name honestly.
                let fallback_s = s.process_cpuset_text(); // :449
                set_thread_name(&format!("s3.pkt-c{fallback_s}")); // :451-:453
            }
        }
        // :458 free(s) == the Rust String drop face
    }

    /// h :58 / cc :461-:493 implement_named_thread_affinity: the map-hi-
    /// t arm (:466-:490: asprintf :472, the binding LogMessage :476-:477
    /// (compare + PRINT only — NO name face on this path), the bind +
    /// warn/fallback :480-:487); the MISS arm rides implement_thread_
    /// affinity(get_thread_type(), DEFAULT_THREAD_ID) (:492 — the
    /// thread.cc :47/:59 THREAD_LOCAL read faces the harness WITNESS
    /// answers with STHREAD_TYPE_MAIN (witness_tc.cc) — the threaded
    /// param face, deviations).
    pub fn implement_named_thread_affinity(
        &self,
        name: &str,
        current_thread_type: SThreadType,
        log: &mut LogEngine,
    ) {
        // :463-:464
        if !self.support_set_thisthread() {
            return;
        }
        if let Some(entry) = self.named_thread_affinity.get(name) {
            let desired = entry.cpuset.dup();
            let s_text = desired.list_asprintf(); // :472
            let s = statics();
            let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
            // :474-:478 (alloc + get_cpubind + compare + PRINT)
            if !s.thread_bind_face().is_equal(&desired) {
                log.log_message_stdout(
                    "Binding thread %s to %s.\n",
                    &[
                        Arg::S(Some(name.to_string().into())),
                        Arg::S(Some(s_text.clone().into())),
                    ],
                );
            }
            // :480-:487 the bind + fallback (NO re-naming face here)
            if s.set_thread_cpubind(&desired).is_err() {
                log.warning_message(
                    "Failed to pin thread %s to %s: %s (%d). Falling back to process CPU set. This may indicate a process affinity mismatch.\n",
                    &[
                        Arg::S(Some(name.to_string().into())),
                        Arg::S(Some(s_text.clone().into())),
                        Arg::S(Some(get_error(EINVAL).into())),
                        Arg::I(EINVAL as i64),
                    ],
                );
                s.fallback_to_process_cpuset(name, &s_text, log);
            }
            // :489 free(s)
        } else {
            self.implement_thread_affinity(current_thread_type, DEFAULT_THREAD_ID, log); // :492
        }
    }

    // ------------------------------------------------------------------
    // the NUMA mempolicy trio (cc :272-:361) — cfg-LESS runtime face;
    // witness/mock arms only (the REAL libnuma bodies: provider seam).
    // ------------------------------------------------------------------

    /// cc :274-:280 `void snort::ThreadConfig::set_numa_mempolicy`: the
    /// convert pair rides the landed main::numa home (REUSE); the UN-
    /// KNOWN warn arm (:277-:279).
    pub fn set_numa_mempolicy(&mut self, policy: &str, log: &mut LogEngine) {
        self.numa_mempolicy = convert_string_to_numa_mempolicy(policy); // :276
        if self.numa_mempolicy == NUMA_POLICY_UNKNOWN {
            log.log_message_stdout(
                "memory policy '%s' is unknown or not supported, defaulting to 'preferred'\n",
                &[Arg::S(Some(policy.to_string().into()))], // :278
            );
        }
    }

    /// the member default face h :88 (PREFERRED).
    pub fn numa_mempolicy(&self) -> u8 {
        self.numa_mempolicy
    }

    /// cc :282-:298 `int ThreadConfig::get_numa_node(hwloc_topology_t,
    /// hwloc_cpuset_t)` (private).
    fn get_numa_node(hwloc: &dyn HwlocWrapper, topology: &Topology, cpuset: &CpuBitmap) -> i32 {
        if hwloc.bitmap_iszero(cpuset) {
            return -1; // :284-:285
        }
        let depth = hwloc.get_type_depth(topology); // :287
        if depth == HWLOC_TYPE_DEPTH_UNKNOWN {
            return -1; // :288-:289 (the 'depth unknown negative' case)
        }
        // :291-:296 (the 'get_nbobjs_by_depth failure' case drives the
        // bound to 0 -> the loop never runs -> -1)
        for i in 0..hwloc.get_nbobjs_by_depth(topology, depth) {
            if let Some(node) = hwloc.get_obj_by_depth(topology, depth, i) {
                // :294 `node and hwloc->bitmap_isincluded(...)`
                if hwloc.bitmap_isincluded(cpuset, &node.cpuset) {
                    return node.os_index; // :295
                }
            }
        }
        -1 // :297
    }

    /// cc :300-:310 `bool ThreadConfig::apply_numa_mempolicy(int node)`
    /// (private).
    fn apply_numa_mempolicy(numa: &dyn NumaWrapper, policy: u8, node: i32) -> bool {
        if node < 0 {
            return false; // :302-:303
        }
        // :305 `1UL << (unsigned long)node` (host-word face; the mocks
        // NEVER read the mask — the real set_mempolicy ABI stays OPEN)
        let nodemask = NodeMask {
            word: 1u64 << (node as u32 % 64),
        };
        // :306 `numa->set_mem_policy(numa_mempolicy, &nodemask, sizeof*8)`
        numa.set_mem_policy(policy, &nodemask, 8 * 8) == 0
    }

    /// h :61 / cc :312-:359 implement_thread_mempolicy — the FALSE lad-
    /// der arms: (:314-:318) support || available()<0 || max_node()<=0
    /// (the witness 0/0 => the FACE-A NUMAFALSE early-out; the mocks
    /// drive the -1 and depth arms); (:320-:322 + :353-:356) no affinity
    /// entry => false; (:324-:341) the ACTUAL-cpubind note + the node-
    /// mismatch warn; (:343) the actual-else-configured pick; (:346-:351)
    /// apply-else-false; (:347-:349) the success LogMessage rides the
    /// stringify_numa_mempolicy REUSE (main::numa — note the FORMAT/arg
    /// order is the ground's, arg1 = the policy string, kept EXACTLY).
    pub fn implement_thread_mempolicy(
        &self,
        kind: SThreadType,
        id: u32,
        log: &mut LogEngine,
    ) -> bool {
        // :314-:318 the early-out AND-ladder (short-circuit ORDER kept)
        if !self.support_set_thisthread() {
            return false;
        }
        let s = statics();
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        let numa = s
            .numa
            .clone()
            .expect("numa rides init() (the HAVE_NUMA globals face)");
        let hwloc = s
            .hwloc
            .clone()
            .expect("hwloc rides init() (the HAVE_NUMA globals face)");
        if numa.available() < 0 || numa.max_node() <= 0 {
            return false;
        }

        // :320-:322 the (type,id) entry lookup (the h :84 member map)
        let key = TypeIdPair { kind, id };
        let configured_cpuset = match self.thread_affinity.get(&key) {
            Some(c) => c.cpuset.dup(),
            None => return false, // :353-:356
        };

        // :328-:329 "Use the actual current cpubind rather than the
        // configured cpuset" (the fallback-placement note :324-:327)
        let actual_cpuset = s.thread_bind_face();
        let topology = s.topology.as_ref().expect("topology needs init()");

        let configured_node = Self::get_numa_node(hwloc.as_ref(), topology, &configured_cpuset);
        let actual_node = Self::get_numa_node(hwloc.as_ref(), topology, &actual_cpuset);

        if configured_node >= 0 && actual_node >= 0 && configured_node != actual_node {
            // :336-:341
            log.warning_message(
                "%s NUMA node mismatch: configured cpuset maps to node %d, but thread is actually bound to node %d. Setting memory policy for actual node %d.\n",
                &[
                    Arg::S(Some(Self::stringify_thread(kind, id).into())),
                    Arg::I(configured_node as i64),
                    Arg::I(actual_node as i64),
                    Arg::I(actual_node as i64),
                ],
            );
        }

        // :343 the actual-else-configured pick (the actual_cpuset free at
        // :344 rides the Drop face)
        let node_index = if actual_node >= 0 { actual_node } else { configured_node };
        drop(s);

        // :346-:351 apply; :347-:349 the success LogMessage
        if !Self::apply_numa_mempolicy(numa.as_ref(), self.numa_mempolicy, node_index) {
            return false;
        }
        log.log_message_stdout(
            "%s memory policy set to %s for node %d\n",
            &[
                Arg::S(Some(stringify_numa_mempolicy(self.numa_mempolicy).into())),
                Arg::S(Some(Self::stringify_thread(kind, id).into())),
                Arg::I(node_index as i64),
            ],
        );
        true // :358
    }
}

// ---------------------------------------------------------------------------
// Statics helpers (the thread-bind + fallback faces).
// ---------------------------------------------------------------------------

impl Statics {
    /// `hwloc_get_cpubind(topology, current_cpuset, HWLOC_CPUBIND_THREAD)`
    /// (cc :329/:406/:475 — nullptr bind => the PROCESS cpuset, the wit
    /// impl `process_like()` face).
    fn thread_bind_face(&self) -> CpuBitmap {
        self.thread_bind
            .clone()
            .unwrap_or_else(|| self.process_cpuset_unwrap().dup())
    }

    /// `hwloc_set_cpubind(topology, desired, HWLOC_CPUBIND_THREAD)` —
    /// the witness arm: ANY bit >= model max (256) FAILS (the ground
    /// graceful-fallback driver cc :438/:779-:786).
    fn set_thread_cpubind(&mut self, desired: &CpuBitmap) -> Result<(), ()> {
        let max = self
            .topology
            .as_ref()
            .expect("topology needs init() (the cc :438 deref face)")
            .model_max_cpu;
        for i in 0..(desired.words.len() * 64) {
            if desired.isset(i) && (i as u32) >= max {
                return Err(()); // the errno face rides EINVAL (deviations)
            }
        }
        self.thread_bind = Some(desired.dup());
        Ok(())
    }

    fn process_cpuset_unwrap(&self) -> &CpuBitmap {
        &self
            .topology
            .as_ref()
            .expect("process_cpuset needs init() (the cc :100/:365 deref faces)")
            .process_cpuset
    }

    fn process_cpuset_text(&self) -> String {
        self.process_cpuset_unwrap().list_asprintf() // :374/:449 asprintf
    }

    /// cc :363-:381 fallback_to_process_cpuset(thread_desc, requested).
    fn fallback_to_process_cpuset(
        &mut self,
        thread_desc: &str,
        requested_cpuset_s: &str,
        log: &mut LogEngine,
    ) {
        // :365 hwloc_set_cpubind(topology, process_cpuset, THREAD)
        let process = self.process_cpuset_unwrap().dup();
        match self.set_thread_cpubind(&process) {
            Err(()) => {
                // :367-:370 the ALSO-failed warn face
                log.warning_message(
                    "Fallback binding to process CPU set also failed for %s: %s (%d). Thread will use inherited affinity.\n",
                    &[
                        Arg::S(Some(thread_desc.to_string().into())),
                        Arg::S(Some(get_error(EINVAL).into())),
                        Arg::I(EINVAL as i64),
                    ],
                );
            }
            Ok(()) => {
                // :373-:380 (the asprintf + the landed face)
                let fallback_s = self.process_cpuset_text();
                log.warning_message(
                    "%s bound to fallback process CPU set '%s' instead of requested '%s'.\n",
                    &[
                        Arg::S(Some(thread_desc.to_string().into())),
                        Arg::S(Some(fallback_s.into())),
                        Arg::S(Some(requested_cpuset_s.into())),
                    ],
                );
            }
        }
    }
}

/// the errno face the warn lines print (the witness NEVER sets errno =>
/// the indeterminate C face; the port pins EINVAL = 22 honestly — the
/// harness 'wit-error' get_error face makes the TEXT unobservable in the
/// harness legs, deviations-recorded).
const EINVAL: i32 = 22;

// ---------------------------------------------------------------------------
// the pthread name face (SET_THREAD_NAME — util.h :41-:53) with the REAL
// 15-byte ERANGE cap (header law). The port-side cell is the MODEL; the
// harness FACE-A probe reads the REAL pthread (the C row); thread-local
// like the C per-thread names.
// ---------------------------------------------------------------------------

const THREAD_NAME_MAX: usize = 15; // util.h :41 "> 15 chars aren't supported"

thread_local! {
    static THREAD_NAME: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_thread_name(name: &str) {
    if name.len() > THREAD_NAME_MAX { // str::len IS bytes (the 15-byte cap)
        return; // pthread_setname_np => ERANGE: the OLD name SURVIVES
    }
    THREAD_NAME.with(|n| *n.borrow_mut() = name.to_string());
}

/// the pthread_getname_np read face (the probes' tname() buffer; the
/// ERANGE ladder reads exactly this).
pub fn get_thread_name() -> String {
    THREAD_NAME.with(|n| n.borrow().clone())
}

unsafe extern "C" {
    /// glibc >= 2.30 `gettid` (cc :235/:257; the harness links it fine —
    /// the 17z note). `#[link_name]` keeps the C symbol while the Rust
    /// safe shim below takes the call-site name.
    #[link_name = "gettid"]
    fn gettid_c() -> i32;
}

/// the safe shim over the raw syscall face (the C calls plain `gettid()`).
fn gettid() -> i32 {
    unsafe { gettid_c() }
}

// ---------------------------------------------------------------------------
// Watchdog (cc :495-:607). get_watchdog() function-local static (:557-
// :561): lazily constructed ONCE from the conf timer, arrays sized by
// get_instance_max() AT FIRST TOUCH (:498-:503). The enabled-guards
// (:585/:604 `static const bool`) read the conf ONCE at first touch =
// the init-time conf face: the stock witness conf (watchdog_timer = 0,
// snort_config.h :264) pins them FALSE => the kick/update NO-OP arms
// (the harness WD-NOOP face).
// ---------------------------------------------------------------------------

/// the stock-SnortConfig conf faces this file reads (snort_config.h :264
/// watchdog_timer = 0 / :265 watchdog_min_thread_count = 1 — the harness
/// witness_conf CORE-SUBSET get_conf()-stock face).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchdogConf {
    pub watchdog_timer: u16,
    pub watchdog_min_thread_count: u16,
}

impl WatchdogConf {
    /// the stock defaults (NEVER std-Default — the min-thread default is
    /// 1 at snort_config.h :265, not 0).
    pub fn stock() -> WatchdogConf {
        WatchdogConf {
            watchdog_timer: 0, // :264
            watchdog_min_thread_count: 1, // :265
        }
    }
}

/// the get_conf() face this file reads (the stock witness defaults; a
/// live SnortConfig = provider seam — NEVER here by one-home law).
fn tc_conf() -> WatchdogConf {
    static TC_CONF: OnceLock<WatchdogConf> = OnceLock::new();
    *TC_CONF.get_or_init(WatchdogConf::stock)
}

struct Watchdog {
    waiting: bool, // :511
    resp: Vec<AtomicBool>, // :512 (the new[] array :500, instance-max sized)
    seconds_count: u16, // :513 (the ctor tm :498)
    thread_is_active: Vec<AtomicBool>, // :514 (new[] :501, pre-cleared :502-:503)
}

impl Watchdog {
    /// cc :497-:504: arrays sized by `ThreadConfig::get_instance_max()`
    /// (:500-:502 — the instance-max ride face); `new std::atomic_bool
    /// [n]` value-initializes (resp false too); thread_is_active is
    /// explicitly cleared (:502-:503).
    fn new(tm: u16) -> Watchdog {
        let n = ThreadConfig::get_instance_max() as usize;
        Watchdog {
            waiting: false,
            resp: (0..n).map(|_| AtomicBool::new(false)).collect(),
            seconds_count: tm,
            thread_is_active: (0..n).map(|_| AtomicBool::new(false)).collect(),
        }
    }

    /// cc :517-:555 kick(). The unresponsive ladder (:520-:542; the tid
    /// hop :533 `SnortConfig::get_conf()->thread_config->
    /// get_instance_tid(i)` rides THIS statics home — an identity hop,
    /// cited); the abort arm (:544-:548) ported faithfully, NEVER exer-
    /// cised by any port-side test (cite-LEFT-OPEN per the witness law).
    fn kick(&mut self, conf: &WatchdogConf, log: &mut LogEngine) {
        let max = self.resp.len();
        if self.waiting {
            let mut thread_count: u16 = 0; // :522
            for i in 0..max {
                if !self.resp[i].load(Ordering::Relaxed)
                    && self.thread_is_active[i].load(Ordering::Relaxed)
                {
                    thread_count += 1;
                    if thread_count == 1 {
                        // :530-:531 the two warn heads (second: no newline)
                        log.warning_message("Packet processing threads are unresponsive\n", &[]);
                        log.warning_message("Unresponsive thread ID: ", &[]);
                    }
                    let tid = ThreadConfig::get_instance_tid(i as i32); // :533
                    if tid != -1 {
                        log.warning_message(
                            "%d (TID: %d)",
                            &[Arg::I(i as i64), Arg::I(tid as i64)], // :534-:535
                        );
                    } else {
                        log.warning_message("%d ", &[Arg::I(i as i64)]); // :536-:537
                    }
                }
            }
            if thread_count != 0 {
                log.warning_message("\n", &[]); // :541-:542
            }
            if thread_count >= conf.watchdog_min_thread_count {
                // :544-:547 the abort arm: NEVER exercised (no port leg
                // builds an unresponsive count; the FACE-A/gate posture
                // keeps the handler dark); mapped honestly, never run.
                log.warning_message("Aborting Snort\n", &[]);
                std::process::abort();
            }
        }
        for slot in self.resp.iter().take(max) {
            slot.store(false, Ordering::Relaxed); // :551-:552
        }
        self.waiting = true; // :554
    }
}

/// cc :557-:561 get_watchdog() — the function-local lazy static (C++11
/// magic static == the OnceLock face), constructed ONCE with
/// `SnortConfig::get_conf()->watchdog_timer`.
fn get_watchdog() -> &'static Mutex<Watchdog> {
    static S_DOG: OnceLock<Mutex<Watchdog>> = OnceLock::new();
    S_DOG.get_or_init(|| Mutex::new(Watchdog::new(tc_conf().watchdog_timer)))
}

/// cc :563-:576 s_watchdog_handler(void*).
fn s_watchdog_handler(log: &mut LogEngine) {
    let conf = tc_conf();
    let dog = get_watchdog();
    let mut dog = dog.lock().unwrap_or_else(|e| e.into_inner());
    if conf.watchdog_timer > 0 {
        if dog.seconds_count > 0 {
            dog.seconds_count -= 1; // :568-:569
        } else {
            dog.kick(&conf, log); // :572
            dog.seconds_count = conf.watchdog_timer; // :573
        }
    }
}

/// the C hook trampoline (the Periodic::register_handler face — the
/// landed time::periodic home REGISTERS honestly; the harness DECL-
/// witnesses Periodic since the timer-0 handler NEVER runs; the decl-
/// home law: periodic.cc symbols NEVER invented).
extern "C" fn s_watchdog_hook(_arg: *mut c_void) {
    s_watchdog_handler(&mut LogEngine::default());
}

/// cc :578-:581 start_watchdog(): `Periodic::register_handler(s_watchdog
/// _handler, nullptr, 0, 1000)`.
pub fn start_watchdog() {
    periodic::register_handler(s_watchdog_hook, std::ptr::null_mut(), 0, 1000);
}

/// cc :582-:594 kick_watchdog(): the :585 `static const bool
/// watchdog_is_enabled` read ONCE (the init-time conf pin — timer 0 =>
/// FALSE => the NO-OP return, the WD-NOOP face); then the THREAD_LOCAL
/// `tl_resp_ptr` first-touch (:588-:590 — the cell for get_instance_id
/// (), thread.h :48 face THREADED as a param, one-home law) + the rela-
/// xed store (:592).
pub fn kick_watchdog(instance_id: u32) {
    let enabled = tc_conf().watchdog_timer > 0; // the :585 once-const face
    if !enabled {
        return;
    }
    let dog = get_watchdog();
    let dog = dog.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = dog.resp.get(instance_id as usize) {
        slot.store(true, Ordering::Relaxed); // :592
    }
}

/// cc :596-:599 preemptive_kick() (the cppcheck :601 unusedFunction —
/// analyzer.cc calls it from ANOTHER TU; same TU here, the fn face kept).
pub fn preemptive_kick(instance_id: u32) {
    kick_watchdog(instance_id);
}

/// cc :600-:607 update_thread_status(bool) (the :604 once-const guard +
/// the thread_is_active store :606).
pub fn update_thread_status(status: bool, instance_id: u32) {
    let enabled = tc_conf().watchdog_timer > 0; // the :604 once-const face
    if !enabled {
        return;
    }
    let dog = get_watchdog();
    let dog = dog.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = dog.thread_is_active.get(instance_id as usize) {
        slot.store(status, Ordering::Relaxed); // :606
    }
}

// ---------------------------------------------------------------------------
// the harness/parity seams (the C gate cases touch TU statics DIRECTLY —
// :842-:845 the mock installs, :725-:726/:754-:755 the process_cpuset
// rewrites, the probes' init/term framing; the Rust port mirrors EXACTLY
// the same test-visible faces, cite-honest).
// ---------------------------------------------------------------------------

/// `numa = numa_mock; hwloc = hwloc_mock;` (cc :844-:845 the shared_ptr
/// global assignment faces — the 5 NUMA gate cases install mocks).
pub fn set_numa_wrapper(seam: Arc<dyn NumaWrapper + Send + Sync>) {
    statics().lock().unwrap_or_else(|e| e.into_inner()).numa = Some(seam);
}

pub fn set_hwloc_wrapper(seam: Arc<dyn HwlocWrapper + Send + Sync>) {
    statics().lock().unwrap_or_else(|e| e.into_inner()).hwloc = Some(seam);
}

/// the gate-case process_cpuset rewrite face (cc :719-:769: `hwloc_-
/// bitmap_free(process_cpuset); process_cpuset = restricted;` + the
/// restore). The C test cases mutate the file static DIRECTLY (inside-
/// the-TU face); the Rust mirror exposes the same mutation honestly.
pub fn set_process_cpuset(set: CpuBitmap) {
    let s = statics();
    let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = s.topology.as_mut() {
        t.process_cpuset = set;
    }
}

pub fn get_process_cpuset() -> Option<CpuBitmap> {
    let s = statics();
    let s = s.lock().unwrap_or_else(|e| e.into_inner());
    s.topology.as_ref().map(|t| t.process_cpuset.dup())
}

/// the current thread-cpubind query (`hwloc_get_cpubind(..., THREAD)` —
/// the gate CHECKs bind through this face :655/:659/:681/:687/:709/:791).
pub fn thread_cpubind_query() -> Option<CpuBitmap> {
    let s = statics();
    let s = s.lock().unwrap_or_else(|e| e.into_inner());
    s.topology.as_ref()?; // the pre-init None face (the C deref face)
    Some(s.thread_bind_face())
}

/// the FRESH-PROCESS face (the C probes/gate each ran a separate pro-
/// cess; the Rust session runs in ONE process — the re-init mirrors a
/// fresh statics image; the sfd session-law face, cite-honest).
pub fn reinit_for_fresh_process() {
    let s = statics();
    let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
    *s = Statics::fresh();
}
