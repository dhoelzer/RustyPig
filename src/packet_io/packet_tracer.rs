// Port of snort3 src/packet_io/packet_tracer.h 166 L (md5 face-pinned by
// the 23f harness ground-identity arm EVERY build) + packet_tracer.cc
// 739 L (md5 face-pinned likewise) @ fe29cbe (row 23f — THE THIRD REAL
// GATE ROW: the cc's OWN in-TU Catch block :461-:738 = EXACTLY-10
// TEST_CASE "[PacketTracer-tag]" faces over EXACTLY-49 CHECK legs,
// host-green EVERY build at the harness — the runner tail is
// RUNNER-MEASURED (the parity twin's GATE window carries the
// self-measured census that maps the cite faces; NEVER typed here)).
//
// THE CLASS (h :48-:133): a per-thread packet-tracing singleton; the
// thread_init/term pair (h :58-:59) manages the THREAD_LOCAL
// s_pkt_trace (h :92, cc :60) and every static entry point derefs it.
//
// THE C -> Rust laws bank on this row (each cited at KNOWN DEVIATIONS
// row 23f):
// - THE SINGLETON LAW (the 23a static-class precedent; the Trough 23d
//   law re-ridden): NO thread_local, no static mut, ZERO unsafe. The C
//   file-statics that SURVIVE a tracer rebuild within one thread
//   (cc :65 global_mutes, :67 log_file = "-", :68 config_status =
//   false) + the THREAD_LOCAL pointer land as fields on a caller-owned
//   TraceThreadWorld; the tracer itself is caller-owned (the one
//   global in C == the ONE value in Rust, the sfaq precedent face).
//   The C null-guard legs (the is_* ternaries :80/:83/:227 + the
//   set_constraints :234 / activate :274 early-returns) are
//   observable-free once the value is owned — cited; the legs that
//   DEREF without a guard in C (log :192, pause :253, unpause :258,
//   the timer :322-:335) are the thread-must-exist contract mirrored
//   by construction: the harness DEC + the ground suite NEVER arm them
//   with no tracer (measured cc :510-:737 — the pause/unpause pair sits
//   only between thread_init and thread_term).
// - statics -> methods: every C static reads the thread singleton, so
//   every Rust leg is an &mut self / &self method (the C static faces
//   ride the two-world method split where the seed survives rebuilds).
// - h :96 `Stopwatch<SnortClock>* pt_timer` (heap new/delete, cc :343/
//   :366) -> a VALUE field REUSING the landed time/stopwatch.rs home
//   (20b; NEVER re-forked, one-home law); the raw-pointer shape is
//   observable-free, cited.
// - h :97 `FILE* log_fh = stdout` -> the LogFh::{Stdout, File} face via
//   the landed log/text_log.rs Handle precedent; open_file :424 fopen
//   "a+" -> OpenOptions append+read (the 23f DEC pins open-OK +
//   open-fail-fallback faces).
// - cc :344-:346 `new char[max]()` x2 + debug_session new[PT_DEBUG_
//   SESSION_ID_SIZE] :346 -> zeroed Vec<u8> with the explicit NUL
//   invariant (buffer[blen] == 0, the vsnprintf face). debug_session is
//   allocated and NEVER read in the C (dtor delete :363 only) — the
//   member face rides honest, cited.
// - every printf leg goes through the landed crate::utils::cfmt (the
//   messages-home law); populate_buf (cc :369-:378) lands the vsnprintf
//   cap semantics VERBATIM: len < space -> append + NUL + count;
//   else -> the space-1 prefix lands, NUL at the cap, len := 2047 —
//   the DEC overflow face pins 2047 = MAX_BUFF_SIZE - 1 (cc :73).
//   The ASCII byte-length == the C printf return at every pinned
//   format face (cited; the DEC legs ride %s/%d literals only).
// - h :115 `PacketConstraints constraints` — THE row's REUSE payoff:
//   the 23e-landed crate::packet_io::packet_constraints home TYPES the
//   member directly (ONE home, NEVER re-forked); update_constraints
//   cc :404 rides its Clone; the activate shell-match leg cc :288
//   rides its packet_match (THE cross-row consumer, DEC-pinned); the
//   banner rides the landed SfIp::ntop + utils::int_vector_to_str
//   (util.rs :223, the C default-delim face util.h :125) + cfmt.
// - THE FOUR WALLS (harness DECL-mirror faces; Rust-side seams):
//   StreamLog (stream/stream_log.h NEVER landed — the activate arms
//   :296-:315 route via the row-scoped StreamLogFace seam, the 23a
//   seam precedent; the add_eth default arg h :34 lands explicit,
//   cited), BatchedLogger (log/batched_logger.h NEVER landed — the
//   buffered legs :114/:160 + the UNCONDITIONAL term flush :120 route
//   via BatchedLogFace), the Packet/Active owners (22b mirror law:
//   row-scoped READ faces below cite active.h :98/:190/:217 — the
//   honest cold face has drop_reason None, DEC-pinned; the act_str
//   table lives active.cc, NEVER linked at the harness), and the DAQ
//   leg REUSES the 23b-landed SFDAQInstance::set_packet_trace_data
//   (cc :437 consumer at the LANDED home — one-home, the closed-seam
//   face; assert(p) :436 rides the NDEBUG-off face, cited).
// - h :135-:163 PacketTracerSuspend / PacketTracerUnsuspend RAII: the
//   C needs the singleton for the static calls; the Rust models the
//   SEMANTICS as pause_n (the Suspend ctor leg) and the saved-count
//   restore pair suspend_scoped/unsuspend_scoped — shapes cited; the
//   DEC pins the ladder arithmetic (2 pauses / restore-2 faces).
// - assert(!s_pkt_trace) (cc :91) + assert(s_pkt_trace->pause_count)
//   (cc :258): the harness/SDK build runs -DNDEBUG (every face measured
//   with the pair OFF — the 23-era law); the port omits them,
//   observable-free AT THE BUILD FACE, cited (the DEC NEVER re-inits
//   over a live tracer and NEVER unpauses a zero count).
// - get_mute (cc :262-:270): the null-tracer arm (:265-:266: bump,
//   return val-1, NO mutes push) rides TraceThreadWorld; the
//   with-tracer arm bumps + pushes and returns mutes.size()-1 — the
//   DEC census face pins both across a term/init rebuild.
// - the virtual dump_to_daq (h :127, cc :434-:438; the test override
//   cc :500-:502): NO vtable — one concrete leg to the landed
//   provider (the C virtual existed ONLY for the unit-test stub,
//   cited).
// - SO_PUBLIC (h :69-:88) + THREAD_LOCAL (h :92): link/decoration
//   faces, cite-never-land.
// - template<typename T> _thread_init (h :118, cc :89-:93): a unit-
//   test seam per the C comment :88; NO Rust twin — vacuous under the
//   owned law (cited).
// - cc :54-:62 the _WIN64 s_pkt_trace ifdef arm: the non-Windows face
//   (namespace-scoped member definition) is THE build face — cite.

use std::fs::OpenOptions;
use std::io::Write;

use crate::detection::rtn_checks::{IAT_4, IAT_6};
use crate::log::messages::{LogEngine, Phase};
// (the cfmt Arg rides its OWN home direct, the file_log.rs:79 precedent —
// messages re-privates it via its use stmt, E0603 face measured):
use crate::main::thread::{NamingConfig, ThreadState, get_instance_file};
use crate::packet_io::packet_constraints::{ConstraintPacketFace, PacketConstraints};
use crate::packet_io::sfdaq::DAQ_PKT_FLAG_TRACE_ENABLED;
use crate::packet_io::sfdaq_instance::SFDAQInstance;
use crate::time::clock_defs::{SnortClock, to_nsecs};
use crate::time::stopwatch::Stopwatch;
use crate::utils::cfmt::cfmt;
use crate::utils::cfmt::Arg;
use crate::utils::util::int_vector_to_str;

/// cc :72 `#define PT_DEBUG_SESSION_ID_SIZE ((39+1+5+1+2+1+39+1+5+1+3+1
/// +2+1+10+1+2+1+10+32)+1)` — the macro sum: 159 (the harness FACE-A
/// pins the macro face VERBATIM).
pub const PT_DEBUG_SESSION_ID_SIZE: usize =
    (39 + 1 + 5 + 1 + 2 + 1 + 39 + 1 + 5 + 1 + 3 + 1 + 2 + 1 + 10 + 1 + 2 + 1 + 10 + 32) + 1;

/// cc :73 `static constexpr int max_buff_size = 2048`.
pub const MAX_BUFF_SIZE: usize = 2048;

/// h :54 `typedef uint8_t TracerMute` (FACE-A pins the width: 1 byte).
pub type TracerMute = u8;

/// h :97 `FILE* log_fh` — the handle face via the text_log Handle
/// precedent (cited): Stdout is the C `stdout` sentinel the legs
/// compare (:107/:154/:358 — the dtor fclose-gate face lives in File's
/// drop, cited next to the struct).
#[derive(Debug)]
pub enum LogFh {
    Stdout,
    File(std::fs::File),
}

/// The C thread-statics that SURVIVE a tracer destroy+rebuild in one
/// thread (cc :65/:67/:68) — caller-owned per the singleton law.
#[derive(Debug, Clone, Default)]
pub struct TraceThreadWorld {
    /// cc :65 `static THREAD_LOCAL struct{ unsigned val = 0; } global_mutes`
    pub global_mutes: u32,
    /// cc :67 `static std::string log_file = "-"` — the initial face EXACT
    pub log_file: String,
    /// cc :68 `static bool config_status = false`
    pub config_status: bool,
}

impl TraceThreadWorld {
    /// the C initial face (cc :65/:67/:68) as an explicit ctor (the
    /// "-" NSDMI face is the reason a bare Default is WRONG here):
    pub fn new() -> Self {
        TraceThreadWorld { global_mutes: 0, log_file: "-".to_string(), config_status: false }
    }

    /// cc :85-:86 set_log_file (static): writes the thread-static.
    pub fn set_log_file(&mut self, file: &str) {
        self.log_file = file.to_string();
    }

    /// cc :246-:251 configure (static): log_file = file_name THEN
    /// config_status = status (assignment order face, cc :249-:250):
    pub fn configure(&mut self, status: bool, file_name: &str) {
        self.log_file = file_name.to_string();
        self.config_status = status;
    }

    /// cc :262-:270 get_mute, the NO-TRACER arm (:265-:266): bump the
    /// census, return val-1, NO mutes push (the DEC census face).
    pub fn get_mute_threadless(&mut self) -> TracerMute {
        self.global_mutes += 1;
        (self.global_mutes - 1) as TracerMute
    }
}

/// The row-scoped activate READ face (the 22b Packet-MIRROR law at the
/// activate legs: cc :277 `p->pkth->flags & DAQ_PKT_FLAG_TRACE_ENABLED`
/// + cc :294 the is_ip() gate + cc :288 the constraints read):
#[derive(Debug)]
pub struct ActivateReadFace<'a> {
    pub pkth_flags: u32,                   // :277 p->pkth->flags
    pub pkt: &'a ConstraintPacketFace<'a>, // :288 packet_match(p) (23e REUSE)
}

impl ActivateReadFace<'_> {
    /// cc :294 `!p->ptrs.ip_api.is_ip()` — ip.h :83 is_ip() = is_ip4()
    /// or is_ip6() (IAT_4|IAT_6 TRUE; IAT_NONE/IAT_DATA FALSE — the
    /// 23e has_ip law re-ridden through the landed IpApiLite iat face).
    pub fn is_ip(&self) -> bool {
        let iat = self.pkt.ip_api.iat;
        iat == IAT_4 || iat == IAT_6
    }
}

/// The row-scoped dump(Packet*) READ face (cc :145-:147):
/// p->active->get_drop_reason() (active.h :190 inline over the private
/// field :217 the real setter active.cc :1050 NEVER lands -> the honest
/// cold face is None, DEC-pinned) + get_action_string() (active.h :98
/// inline over the act_str class-static the harness witness mirrors).
#[derive(Debug, Default)]
pub struct DumpReadFace<'a> {
    pub drop_reason: Option<&'a str>, // active.h :217 (default nullptr)
    pub action_string: &'a str,       // the act_str[ACT][AST] face
}

/// The StreamLog seam (stream_log.h NEVER landed — THE wall; the DECL
/// faces stream_log.h :34-:38 are header-pinned at the harness; the C
/// add_eth default arg h :34 lands as an explicit arg — the 23e
/// default-arg-split precedent): the activate arms cc :296-:315.
pub trait StreamLogFace {
    fn add_ip_header_info(&mut self, add_eth: bool); // :296 (default-true) / :315 (explicit false)
    fn add_eth_header_info(&mut self);               // :297/:311
    fn add_packet_type_info(&mut self);              // :298/:312
    fn stream_is_cbd_enabled(&self) -> bool;         // :305 (cold face false)
}

/// The BatchedLogger seam (batched_logger.h NEVER landed — THE wall;
/// statics -> trait methods): the buffered legs cc :114-:115/:160-:161
/// + the UNCONDITIONAL term flush :120.
pub trait BatchedLogFace {
    fn log(&mut self, use_syslog: bool, msg: &[u8], len: usize);
    fn flush_thread_buffers(&mut self);
}

/// h :48-:133 class PacketTracer — the owned facade (fields = the
/// protected h :96-:115 face, pub per the Trough facade law; ZERO
/// allows).
// NO derive(Debug): the LANDED 20b Stopwatch<SnortClock> carries none and
// this ledger NEVER edits another row's landed home for a derive (the
// packet_constraints.rs:261 precedent: hand-derive where the members need it);
// no test face needs the Debug shape here.
pub struct PacketTrace {
    pub pt_timer: Stopwatch<SnortClock>,   // h :96 (heap ptr -> value, cited)
    pub log_fh: LogFh,                     // h :97
    pub buffer: Vec<u8>,                   // cc :344 zeroed face + NUL invariant
    pub daq_buffer: Vec<u8>,               // cc :345
    pub debug_session: Vec<u8>,            // cc :346 (NEVER read in C, cited)
    pub mutes: Vec<bool>,                  // h :103
    pub buff_len: u32,                     // h :105
    pub daq_buff_len: u32,                 // h :106
    pub pause_count: u32,                  // h :107
    pub user_enabled: bool,                // h :109
    pub daq_activated: bool,               // h :110
    pub shell_enabled: bool,               // h :111
    pub active: bool,                      // h :112
    pub debugstr: String,                  // h :114 (NEVER written in C, cited)
    pub constraints: PacketConstraints,    // h :115 — THE 23e REUSE (one home)
    pub dbg_str: String,                   // h :132 private member face honest
    /// ctor-time snapshot of the thread-static the open_file leg reads
    /// (cc :418-:419; the re-configure seed reaches only the NEXT
    /// ctor — the C exactly so, cited):
    log_file_snap: String,
}

/// thread_init (cc :95-:96 -> _thread_init cc :89-:93 fused by the
/// owned law) + the ctor cc :342-:354: the caller builds ONE tracer
/// per thread; the open_file leg runs INSIDE (:352) and the
/// user_enabled = config_status seed lands LAST (:353 — the ctor-member
/// order face).
pub fn new(
    world: &TraceThreadWorld,
    conf: &NamingConfig,
    ts: &ThreadState,
    log: &mut LogEngine,
) -> PacketTrace {
    let mut t = PacketTrace {
        pt_timer: Stopwatch::default(),                 // :343 new Stopwatch<SnortClock>()
        log_fh: LogFh::Stdout,                          // h :97 NSDMI (open_file overwrites)
        buffer: vec![0u8; MAX_BUFF_SIZE],               // :344 new char[2048]() zero face
        daq_buffer: vec![0u8; MAX_BUFF_SIZE],           // :345
        debug_session: vec![0u8; PT_DEBUG_SESSION_ID_SIZE], // :346 (159-byte face, cited)
        mutes: Vec::new(),                              // :351 resize runs below
        buff_len: 0,                                    // h :105 NSDMI
        daq_buff_len: 0,                                // h :106
        pause_count: 0,                                 // h :107
        user_enabled: false,                            // h :109
        daq_activated: false,                           // h :110
        shell_enabled: false,                           // h :111
        active: false,                                  // h :112
        debugstr: String::with_capacity(256),           // :349 reserve(256)
        constraints: PacketConstraints::default(),      // :404-style default member
        dbg_str: String::with_capacity(256),            // :348 reserve(256)
        log_file_snap: world.log_file.clone(),          // the :418 snapshot read
    };
    t.mutes = vec![false; world.global_mutes as usize]; // :351 mutes.resize(val, false)
    t.open_file(conf, ts, log); // :352
    t.user_enabled = world.config_status; // :353
    t
    // dtor legs = Drop: the C :358-:362 fclose(face) is File-owning-drop
    // in Rust (cited; the C == nullptr guard against double-close rides
    // the same law).
}

impl PacketTrace {
    /// h :73 cc :79-:80 (the null ternary -> the owned law, cited):
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// h :74 cc :82-:83:
    pub fn is_daq_activated(&self) -> bool {
        self.daq_activated
    }

    /// h :71 cc :225-:230: `s_pkt_trace and s_pkt_trace->pause_count`:
    pub fn is_paused(&self) -> bool {
        self.pause_count != 0
    }

    /// h :69-:70 cc :253-:260 pause/unpause (statics; the assert :258
    /// rides the NDEBUG face, cited):
    pub fn pause(&mut self) {
        self.pause_count += 1; // :254
    }

    pub fn unpause(&mut self) {
        self.pause_count -= 1; // :259 (C assert-guards the zero face)
    }

    /// The Suspend RAII shape (h :135-:142): ONE ctor leg = pause();
    /// the dtor leg = unpause(). The DEC walks the bare pair.
    pub fn suspend_scoped(&mut self) {
        self.pause();
    }

    /// The Unsuspend RAII shape (h :144-:163): the ctor drains ALL
    /// pauses counting them; the dtor re-pauses exactly that many. The
    /// saved count returns for the face pin (the C exposes the member
    /// :146):
    pub fn unsuspend_scoped(&mut self) -> u32 {
        let mut saved = 0u32; // :146 saved_pause_count
        while self.is_paused() {
            // :151-:155 while (is_paused()) { unpause(); saved++; }
            self.unpause();
            saved += 1;
        }
        saved
    }

    /// The Unsuspend dtor face (:158-:162): for i in 0..saved { pause() }:
    pub fn restore_saved(&mut self, saved: u32) {
        for _ in 0..saved {
            self.pause();
        }
    }

    /// cc :416-:432 open_file (ctor-run ONLY — h :126): the "-"
    /// sentinel face (:418-:419) vs get_instance_file :423 (LANDED
    /// thread.rs REUSE, the text_log.rs:179 same-consumer law) + fopen
    /// "a+" :424 (append+read face); on failure WarningMessage :428 +
    /// stdout fallback :429 (log_fh NEVER stays null — the C face).
    pub fn open_file(&mut self, conf: &NamingConfig, ts: &ThreadState, log: &mut LogEngine) {
        if self.log_file_snap == "-" {
            self.log_fh = LogFh::Stdout;
            return;
        }
        // :422-:423 (the landed get_instance_file models thread.cc
        // :129-:170 VERBATIM — the log_dir/prefix/id legs):
        let fname = get_instance_file(conf, ts, &self.log_file_snap, log);
        // :424 fopen(fname, "a+"): the a+ face is O_RDWR|O_APPEND|O_CREAT
        // (fopen CREATES a missing file — the DEC D20a open file NEVER
        // existed in the CWD and the C STILL opened it warn-EMPTY; the
        // Rust append+read pair needs the explicit create leg, cited):
        match OpenOptions::new().append(true).read(true).create(true).open(&fname) {
            Ok(f) => self.log_fh = LogFh::File(f),
            Err(_) => {
                log.warning_message(
                    "Could not open %s for packet trace logging\n",
                    &[Arg::S(Some(self.log_file_snap.as_str().into()))],
                );
                self.log_fh = LogFh::Stdout; // :429
            }
        }
    }

    /// cc :232-:244 set_constraints (static): the null-constraints arm
    /// (:237-:241 LogMessage + shell off) vs the update leg (:243).
    pub fn set_constraints(&mut self, cs: Option<&PacketConstraints>, log: &mut LogEngine) {
        match cs {
            None => {
                log.log_message_stdout("Debugging packet tracer disabled\n", &[]); // :239
                self.shell_enabled = false; // :240
            }
            Some(c) => self.update_constraints(c, log),
        }
    }

    /// cc :398-:414 update_constraints: the member copy (:404) + the
    /// debug banner (:408-:410, cfmt format VERBATIM; ntop via the
    /// LANDED SfIp::ntop, the v4 face; int_vector_to_str via the LANDED
    /// util home with the C default ',' — util.h :125) + shell on :412
    /// (the blank line :413 face rides).
    pub fn update_constraints(&mut self, cs: &PacketConstraints, log: &mut LogEngine) {
        self.constraints = cs.clone(); // :404 (23e Clone REUSE)
        let sipstr = self.constraints.src_ip.ntop(false).unwrap_or_default();
        let dipstr = self.constraints.dst_ip.ntop(false).unwrap_or_default();
        log.log_message_stdout(
            "Debugging packet tracer with %s-%hu and %s-%hu %hhu and tenants:%s\n",
            &[
                Arg::S(Some(sipstr.into())),
                Arg::U(u64::from(self.constraints.src_port)),
                Arg::S(Some(dipstr.into())),
                Arg::U(u64::from(self.constraints.dst_port)),
                Arg::U(u64::from(self.constraints.ip_proto)),
                Arg::S(Some(int_vector_to_str(&self.constraints.tenants, ',').into())),
            ],
        );
        self.shell_enabled = true;
    }

    /// cc :272-:319 activate (static) — the WHOLE arm ladder VERBATIM:
    /// the trace-flag arm (:277-:281 masks the LANDED
    /// DAQ_PKT_FLAG_TRACE_ENABLED, restart_timer included), the
    /// user/shell gate (:285-:303), the Shell-match early-out
    /// (:287-:291, the 23e packet_match REUSE), the daq-or-cbd gate
    /// (:305-:316) and the final else (:317-:318).
    pub fn activate(&mut self, p: &ActivateReadFace<'_>, s: &mut dyn StreamLogFace) {
        if p.pkth_flags & DAQ_PKT_FLAG_TRACE_ENABLED != 0 {
            self.daq_activated = true; // :279
            self.restart_timer(); // :280
        } else {
            self.daq_activated = false; // :283
        }

        if self.user_enabled || self.shell_enabled {
            if self.shell_enabled && !self.constraints.packet_match(p.pkt) {
                self.active = false; // :290
                return; // :291
            }
            if !p.is_ip() {
                s.add_eth_header_info(); // :296
                s.add_packet_type_info(); // :297
            } else {
                self.active = true; // :301
                s.add_ip_header_info(true); // :302 (h :34 default add_eth = true)
            }
        } else if self.daq_activated || s.stream_is_cbd_enabled() {
            self.active = false; // :307
            if !p.is_ip() {
                s.add_eth_header_info(); // :311
                s.add_packet_type_info(); // :312
            } else {
                s.add_ip_header_info(false); // :315 (the C explicit false)
            }
        } else {
            self.active = false; // :318
        }
    }

    /// h :88 cc :321-:322 get_time: TO_NSECS(pt_timer->get()) — the
    /// LANDED clock-home to_nsecs REUSE (the non-TSC branch: the ns
    /// identity face, cited at time/clock_defs.rs).
    pub fn get_time(&self) -> u64 {
        to_nsecs(self.pt_timer.get()) as u64
    }

    /// cc :325-:326 start_timer (the cppcheck-retained entry face):
    pub fn start_timer(&mut self) {
        self.pt_timer.start();
    }

    /// cc :329-:330 reset_timer:
    pub fn reset_timer(&mut self) {
        self.pt_timer.reset();
    }

    /// cc :332-:336 restart_timer (reset THEN start — the order face):
    pub fn restart_timer(&mut self) {
        self.pt_timer.reset();
        self.pt_timer.start();
    }

    /// h :124 inline get_debug_session (protected): debugstr.c_str() —
    /// the C NEVER writes debugstr (member face honest, cited):
    pub fn get_debug_session(&self) -> &str {
        &self.debugstr
    }

    /// cc :369-:378 populate_buf (member): the vsnprintf cap law —
    /// fits -> the bytes + NUL + count (:374-:375); else the write STILL
    /// lands space-1 chars + the NUL at the cap and output_len :=
    /// max_buff_size - 1 (:377, the glibc-vs-nprintf truncation face;
    /// DEC overflow pins the 2047 count face).
    fn populate_buf(&mut self, text: &str, to_daq: bool) {
        let (buf, blen) = if to_daq {
            (&mut self.daq_buffer, &mut self.daq_buff_len)
        } else {
            (&mut self.buffer, &mut self.buff_len)
        };
        let buff_space = MAX_BUFF_SIZE - *blen as usize; // :371
        let len = text.len();                            // the vsnprintf return face
        if len < buff_space {
            let start = *blen as usize;
            buf[start..start + len].copy_from_slice(text.as_bytes());
            buf[start + len] = 0; // the vsnprintf NUL face
            *blen += len as u32; // :375
        } else {
            let start = *blen as usize;
            let take = buff_space - 1; // the space-1 write face
            buf[start..start + take].copy_from_slice(&text.as_bytes()[..take]);
            buf[MAX_BUFF_SIZE - 1] = 0; // NUL at the cap
            *blen = (MAX_BUFF_SIZE - 1) as u32; // :377
        }
    }

    /// cc :380-:396 log_va (member): the shell dbg-prefix rebuild legs
    /// (:383-:390: dbg_str = "PktTracerDbg " + get_debug_session
    /// UNLESS msg_only or format == "\n" (the strcmp face :386) +
    /// format; format := dbg_str.c_str()) THEN the buffer split
    /// (:392-:395). The C mutates format via its OWN member dbg_str —
    /// the clone hands cfmt the concatenated face (same face, cited).
    fn log_va(&mut self, format: &str, args: &[Arg<'_>], log_to_daq: bool, msg_only: bool) {
        let fmt: String = if self.shell_enabled && !log_to_daq {
            self.dbg_str.clear(); // :385 (assignment face: reuse of the member scratch)
            self.dbg_str.push_str("PktTracerDbg ");
            if !msg_only && format != "\n" {
                // :386-:387 (the session leg; debugstr NEVER written in C
                // -> the empty-string face rides, cited):
                let ds = self.get_debug_session().to_string();
                self.dbg_str.push_str(&ds);
            }
            self.dbg_str.push_str(format); // :388
            std::mem::take(&mut self.dbg_str) // :389 (format rides it; the
                                              // member scratch face: C keeps
                                              // dbg_str live between legs —
                                              // it is CLEARED :385 next call,
                                              // so take-vs-clone is
                                              // observable-free, cited)
        } else {
            format.to_string()
        };
        let text = cfmt(&fmt, args);
        if log_to_daq {
            self.populate_buf(&text, true); // :393
        } else {
            self.populate_buf(&text, false); // :395
        }
    }

    /// cc :190-:199 log (static): the pause guard (:192) + log_va
    /// (:197). The C printf varargs ride the cfmt &[Arg] face (the
    /// messages-home law; the DEC/gate legs pin %s/%d literals).
    pub fn log(&mut self, format: &str, args: &[Arg<'_>]) {
        if self.is_paused() {
            return;
        }
        self.log_va(format, args, false, false);
    }

    /// cc :201-:210 log_msg_only: pause guard + msg_only = true (:208).
    pub fn log_msg_only(&mut self, format: &str, args: &[Arg<'_>]) {
        if self.is_paused() {
            return;
        }
        self.log_va(format, args, false, true);
    }

    /// cc :179-:188 daq_log (static): pause guard + the daq buffer leg.
    pub fn daq_log(&mut self, format: &str, args: &[Arg<'_>]) {
        if self.is_paused() {
            return;
        }
        self.log_va(format, args, true, false);
    }

    /// cc :212-:223 log(TracerMute, ...): NO pause guard EXACT (the C
    /// gate reads mutes[mute] :214, sets it true AFTER the leg :222 —
    /// the once-until-dump face). The C indexes unchecked (UB beyond
    /// the census); the get() mirrors the in-range face (cited — the
    /// ids OWN the range, C and Rust alike).
    pub fn log_mute(&mut self, mute: TracerMute, format: &str, args: &[Arg<'_>]) {
        if self.mutes.get(mute as usize).copied().unwrap_or(false) {
            return; // :215 ("logged under this mute once")
        }
        self.log_va(format, args, false, false); // :219
        if let Some(m) = self.mutes.get_mut(mute as usize) {
            *m = true; // :222
        }
    }

    /// h :76 cc :262-:270 get_mute (the WITH-tracer arm): bump the
    /// census (:264 — the SAME static both arms share) + the mutes
    /// push_back (:268) + return size()-1 (:269).
    pub fn get_mute(&mut self, world: &mut TraceThreadWorld) -> TracerMute {
        world.global_mutes += 1;
        self.mutes.push(false);
        (self.mutes.len() - 1) as TracerMute
    }

    /// h :61-:62 cc :125-:135 dump(char* output_buff, unsigned len):
    /// the pause guard FIRST (:127-:128), the copy
    /// `min(len, buff_len + 1)` (:130-:132 — the +1 carries the NUL),
    /// the null-out-buff arm NEVER copies (:130; the ground verbosity
    /// case rides dump(nullptr, 0) :685 for the RESET-only face) +
    /// reset(false) UNCONDITIONALLY (:134).
    pub fn dump(&mut self, output: &mut [u8]) {
        if self.is_paused() {
            return;
        }
        let n = std::cmp::min(output.len(), self.buff_len as usize + 1); // :132 the ternary face
        output[..n].copy_from_slice(&self.buffer[..n]); // :131 memcpy face
        self._reset(false); // :134
    }

    /// h :62 cc :137-:166 dump(Packet*): the pause guard (:139), the
    /// `buff_len > 0 and (user or shell)` gate (:142-:143), the
    /// drop_reason -> "Verdict Reason: %s, %s\n" leg (:145-:147 — the
    /// C routes it through the static log: the pause re-check is
    /// observable-free since the guard above ran, cited), then the
    /// buffered/flush split (:148-:162) + reset(false) (:165).
    pub fn dump_packet(
        &mut self,
        p: &DumpReadFace,
        log: &mut LogEngine,
        b: &mut dyn BatchedLogFace,
    ) {
        if self.is_paused() {
            return;
        }
        if self.buff_len > 0 && (self.user_enabled || self.shell_enabled) {
            if let Some(reason) = p.drop_reason {
                // :147 PacketTracer::log(...) — the static leg with the
                // Verdict format VERBATIM (the action_string rides the
                // act_str face, cited at DumpReadFace):
                self.log(
                    "Verdict Reason: %s, %s\n",
                    &[Arg::S(Some(reason.into())), Arg::S(Some(p.action_string.into()))],
                );
            }
            if !log.use_log_buffered() {
                // :149 LogMessage(log_fh, "%s\n", buffer):
                self.emit_logmessage(log);
            } else {
                // :152-:153 the newline append face (room law: only when
                // buff_len < max-1):
                if (self.buff_len as usize) < MAX_BUFF_SIZE - 1 {
                    self.buffer[self.buff_len as usize] = b'\n';
                    self.buff_len += 1;
                }
                // :154-:161: a REAL file handle -> fprintf %.*s + fflush
                // (NO newline: the :152-:153 append rode it); the stdout
                // handle -> the BatchedLogManager leg:
                match &mut self.log_fh {
                    LogFh::File(f) => {
                        let _ = f.write_all(&self.buffer[..self.buff_len as usize]); // :156
                        let _ = f.flush(); // :157
                    }
                    LogFh::Stdout => {
                        // :160-:161 log(fh, log_syslog(), buffer, len):
                        let len = self.buff_len as usize;
                        b.log(log.log_syslog(), &self.buffer, len);
                    }
                }
            }
        }
        self._reset(false); // :165
    }

    /// h :63 cc :168-:177 daq_dump (static): the pause guard, the
    /// daq_activated-gated dump_to_daq leg, then reset(true)
    /// UNCONDITIONALLY (:176). The virtual dump_to_daq body cc :434-
    /// :438 (assert(p) :436 — the NDEBUG face, cited; :437
    /// set_packet_trace_data(p->daq_msg, daq_buffer, daq_buff_len + 1)
    /// — the +1 carries the NUL EXACTLY) rides the LANDED 23b
    /// SFDAQInstance (one-home; no vtable, cited at the header).
    pub fn daq_dump(&mut self, daq: Option<&mut SFDAQInstance>, daq_msg: u64) {
        if self.is_paused() {
            return;
        }
        // the let-chain pair (edition-2024): the activated gate THEN the
        // Some leg (the cc :171-:175 -> :435-:437 nesting order EXACT):
        if self.daq_activated && let Some(d) = daq {
            let len = (self.daq_buff_len + 1) as usize; // :437 the +1 face
            let _ = d.set_packet_trace_data(daq_msg, &self.daq_buffer[..len]);
        }
        self._reset(true);
    }

    /// cc :98-:123 thread_term (static): the pre-delete flush ladder +
    /// the unconditional batched flush (:120). The delete legs
    /// (:121-:122) are the Drop law: the caller drops the value (the
    /// dtor legs cited above).
    pub fn term(&mut self, log: &mut LogEngine, b: &mut dyn BatchedLogFace) {
        // :100-:101 the gate:
        if self.buff_len > 0 && (self.user_enabled || self.shell_enabled) {
            if !log.use_log_buffered() {
                // :104 LogMessage(fh, "%s\n", buffer):
                self.emit_logmessage(log);
            } else if let LogFh::File(f) = &mut self.log_fh {
                // :107-:110 (`log_fh and log_fh != stdout`: fprintf
                // "%.*s\n" + fflush — the "\n" INSIDE the format this
                // time, :109, vs the dump_packet split, cited):
                let _ = f.write_all(&self.buffer[..self.buff_len as usize]);
                let _ = f.write_all(b"\n");
                let _ = f.flush();
            } else {
                // :114-:115 the BatchedLogManager::log leg:
                let len = self.buff_len as usize;
                b.log(log.log_syslog(), &self.buffer, len);
            }
        }
        b.flush_thread_buffers(); // :120 UNCONDITIONAL
        // the delete + null legs: Rust drop, cited above.
    }

    /// the shared LogMessage(fh, "%s\n", buffer) leg (:104/:149): the
    /// LOGGED text rides the landed engine through cfmt.
    /// (Caveat cited: the engine Phase::File face carries a borrowed
    /// name the OWNED tracer cannot hand for a transient handle; the
    /// FILE-handle LogMessage legs write the handle directly — the
    /// same bytes, the same "\n", the same append face; the harness
    /// DEC pins the Stdout face — file-open tracers NEVER log before
    /// their legs).
    fn emit_logmessage(&mut self, log: &mut LogEngine) {
        match &mut self.log_fh {
            LogFh::Stdout => {
                let text = String::from_utf8_lossy(&self.buffer[..self.buff_len as usize])
                    .into_owned();
                log.log_message_file(Phase::Stdout, "%s\n", &[Arg::S(Some(text.into()))]);
            }
            LogFh::File(f) => {
                let _ = f.write_all(&self.buffer[..self.buff_len as usize]);
                let _ = f.write_all(b"\n");
                let _ = f.flush();
            }
        }
    }

    /// cc :440-:455 reset (member): the reset_daq_log split — the daq
    /// arm (:444-:445 len+0 byte) vs the user arm (:449-:453 len, 0
    /// byte AND the mute re-arm loop — fill(false) the same face).
    fn _reset(&mut self, reset_daq_log: bool) {
        if reset_daq_log {
            self.daq_buff_len = 0;
            self.daq_buffer[0] = 0;
        } else {
            self.buff_len = 0;
            self.buffer[0] = 0;
            for m in self.mutes.iter_mut() {
                *m = false; // :452-:453
            }
        }
    }
}
