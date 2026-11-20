//! Literal-port arm map of `file_api/file_log.cc` (row 17z — 329 L,
//! NO `file_log.h` exists: `find src -name 'file_log*'` at fe29cbe
//! returns ONLY the .cc and CMakeLists.txt:30 carries it with no .h
//! twin, NEXT.md:112-:115 / flog PLAN "EXISTENCE FIRST"). Every class
//! here is TU-local in C; the harness reaches the whole row through
//! the row TU's only data export (`sin_file[]`, cc:324 — the Rust
//! registry stays a doc-seam, see [`sin_file`] below).
//!
//! Donor oracle: `tools/flog_harness` (tools/fsvc_harness donor, row
//! 17y lineage, NEXT.md:91). The row TU + the real `log/text_log.cc` +
//! `framework/module.cc` compile byte-VERBATIM there (0 grafts;
//! `grep -c TEST_CASE` = 0 and `grep -c UNIT_TEST` = 0 measured; flog
//! PLAN §0). vectors.txt (50 L) is the frozen transcript this module's
//! arms transcriptionally mirror; the REAL text_log.o + module.o in
//! the harness link close every TextLog_/Module residue, so the landed
//! twins `src/log/text_log.rs` and `src/utils/util.rs` are REAL-in-17z
//! PARITY WITNESSES (the 17y snort_protocols ruling, flog PLAN §3 row
//! 1): ZERO edits to either twin this row.
//!
//! Landed twins cited (all UNEDITED this row):
//! * `TextLog_{Init,Term,Print,Putc,Write}` -> src/log/text_log.rs
//!   (`text_log_init` :161, `text_log_term` :206, `flush` :251,
//!   `putc` :279, `write` :302, `print` :343 with the cfmt-variadic-
//!   lite `Arg` array). `TextLog_Puts` is the INLINE at text_log.h:74
//!   (`TextLog_Write(txt, str, strlen(str))` — 5 residues, not 6, flog
//!   PLAN §0 NEW-app row); the port spells the same lowering through
//!   `write(s, s.len())` at every cc Puts arm.
//! * `ConfigLogger::log_flag` show pair (cc:222-:223) ->
//!   src/log/messages.rs:444 ConfigLogger — the SAME landed helper the
//!   finspect show ladder rides (file_inspect.rs:427-:437); the
//!   INDENTION-25 `%*s: %s` line + enabled/disabled words are its own.
//! * `ts_print` + `TIMEBUF_SIZE` 27 -> src/utils/util.rs:9 (27 pin),
//!   `TimeCfg` :60, `ts_print_mmdd` :129 — the row's calls
//!   (cc:147/:157) take the C DEFAULT `yyyymmdd = false` arm
//!   (util.h:122 default arg; util.cc:191-:197 `%02d/%02d-%02d:%02d:%
//!   02d.%06u`), so the mm/dd twin answers the V3/V4 line heads
//!   (`11/14-22:13:20.500000`, vectors.txt:21+).
//! * `sha_to_string` UPPERCASE -> file_lib.rs:590 (conv[] `01234567
//!   89ABCDEF`; the vectors' `[SHA: ABAB...]` UPPERCASE pin, PLAN R3).
//! * `get_UTF8_fname` -> file_lib.rs:1790 (None == the C null outbuf;
//!   ONE visibility widening `fn` -> `pub(crate) fn` this row,
//!   body untouched — deviation row 17z).
//! * free `file_type_name` -> file_config.rs:110 (the null-conf "NA"
//!   arm, PLAN R6; member arm `FileConfigLite::file_type_name`
//!   file_lib.rs:915 answers the vectors' two Type strings via the
//!   CONTINUE/UNKNOWN specials before any rule lookup).
//! * `VerdictName` global table -> file_lib.rs:62 `VERDICT_NAME`
//!   (file_lib.h:38-:39, 8 entries incl. index 7 `FILE_VERDICT_MAX`
//!   -> "INVALID"; the vectors.txt:21-:30 walk ends `INVALID`).
//! * `PegCount`/`PegInfo`/`CountType` -> framework/counts.rs; the
//!   `V2_params` type0=1/end1=1 digits ARE the CountType discriminants.
//! * `Parameter`/`Value` (`is`/`get_bool`) -> framework/parameter.rs
//!   (PtBool=3, PtMax=21 discriminant pins) + framework/value.rs:181
//!   /:196.
//!
//! What stays a SEAM (flog PLAN §3 "stays-seam" rows — UNTOUCHED):
//! `packet_gettimeofday` + wall `gettimeofday` stay injected time
//! inputs (the Clock-injection idiom, text_log.rs:40 precedent, PLAN
//! R1); the `file_log_event` TRAIT-SEAM cluster (file_cache.rs:532
//! `NoopFileCacheEventSink`, file_lib.rs:2314 forwarder, the three
//! frozen test stubs fcache:346/fflows:256/fctx:321) is NOT touched —
//! 17z does NOT wire file.log rendering into them (the C FileLog is an
//! optional inspector riding the bus; R4 "the bus never runs").

use std::cell::RefCell;
use std::rc::Rc;

use super::file_config;
use super::file_lib::{get_utf8_fname, FileInfo, FileEnvLite, VERDICT_NAME, INTRINSIC_EVENT_ID_FILE_VERDICT};
use super::file_inspect::{
    InspectApiRecord, API_OPTIONS, API_RESERVED, INSAPI_VERSION, IT_PASSIVE,
    PT_INSPECTOR, PROBE_SIZEOF_INSPECT_API, PROTO_BIT__NONE,
};
use crate::framework::counts::{CountType, PegCount, PegInfo};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::value::Value;
use crate::log::messages::LogEngine;
use crate::log::text_log::{Clock, TextLog, K_BYTES, M_BYTES, text_log_init, text_log_term};
use crate::utils::cfmt::Arg;
use crate::utils::util::{ts_print_mmdd, TimeCfg, TIMEBUF_SIZE};

// ==================================================================
// file-scope statics (cc:38-:40) — C `static const char*` trio.
// ==================================================================

/// cc:38 `static const char* s_name = "file_log"` — ALSO the
/// DataHandler tag: the LogHandler ctor passes it to
/// `DataHandler(s_name)` (cc:84) and the W1 witness prints it off
/// `DataHandler::module_name` (data_bus.h:95; vectors.txt:13
/// `handler=file_log`).
pub const MODULE_NAME: &str = "file_log";

/// cc:39 `static const char* f_name = "file.log"` — the TextLog_Init
/// target (cc:69).
pub const LOG_FILE_NAME: &str = "file.log";

/// cc:40 `static const char* s_help` — V1 pin `help=log file event to
/// file.log` (vectors.txt:2).
pub const MODULE_HELP: &str = "log file event to file.log";

/// `pub_sub/intrinsic_event_ids.h:69` namespace-scope `const PubKey
/// intrinsic_pub_key` — const => internal linkage per TU (flog PLAN
/// §1: the row .o carries NO U entry for it; scratch `pubkey_sz=16`,
/// vectors.txt:3). The Rust seam models the bus key by name (the
/// MpBusSeam name-args precedent, file_inspect.rs:183) — this is the
/// row TU's TU-local copy (deviation row 17z: PubKey { publisher,
/// thread_instance } becomes just the publisher string; the instance
/// half has no Rust consumer yet).
pub const INTRINSIC_PUB_KEY: &str = "snort";

/// TextLog_Init size args (cc:69 `64*K_BYTES, 1*M_BYTES`; K/M_BYTES
/// text_log.h:41-:42 -> the landed text_log.rs:30-:32 consts). The
/// probe read them back as literals (`buf=65536 file=1048576`,
/// vectors.txt:3) — probe-pinned literals (file_cache_share.rs:69 rule:
/// C-side sizes are pinned, never derived).
pub const TLOG_MAX_BUF: usize = 64 * K_BYTES;
pub const TLOG_MAX_FILE: usize = M_BYTES; // cc:69 `1*M_BYTES` (identity fold)

/// text_log.h:50 — `TextLog_Init(name, maxBuf, maxFile, is_critical=
/// true)`: the row TU passes only three args, so criticality is the
/// header default `true` at cc:69 (an unopenable file.log is FATAL in
/// C; the landed open_log_file models exactly that fatal posture).
pub const TLOG_IS_CRITICAL: bool = true;

const _: () = assert!(TIMEBUF_SIZE == 27); // V1_statics tb=27 (util.h:67)
const _: () = assert!(TLOG_MAX_BUF == 65536); // V1_statics buf=65536
const _: () = assert!(TLOG_MAX_FILE == 1048576); // V1_statics file=1048576

/// V1_statics slot liveness (vectors.txt:3): `tinit=1 tterm=1 ctor=1
/// dtor=1 pinit=0 pterm=0 ssn=0 reset=0` — the record's fn-pointer
/// slots as presence bools, pinned at compile time (the landed
/// fl_api record arms: dl_tinit/dl_tterm, fl_ctor/fl_dtor live;
/// pinit/pterm/ssn/reset nullptr at cc:313-:314/:319-:320).
const _: () = assert!(
    FL_API.tinit && FL_API.tterm && FL_API.ctor && FL_API.dtor
        && !FL_API.pinit && !FL_API.pterm && !FL_API.ssn && !FL_API.reset
);

// ==================================================================
// struct FileLogConfig — cc:42-:46. Defaults matter (flog PLAN §1):
// pkt-time ON (cc:44), sys-time OFF (cc:43).
// ==================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileLogConfig {
    pub log_sys_time: bool, // cc:43 `= false`
    pub log_pkt_time: bool, // cc:44 `= true`
}

impl Default for FileLogConfig {
    fn default() -> Self {
        // the derive would give both-false; C pins pkt-time TRUE —
        // spelled out from the member initializers.
        FileLogConfig { log_sys_time: false, log_pkt_time: true }
    }
}

// ==================================================================
// struct FileLogStats — cc:48-:51 + `static THREAD_LOCAL fl_stats`
// cc:53 + the PegInfo table cc:55-:59. THREAD_LOCAL is TLS at C
// (snort_types.h:71-:73, `__thread` under the copy/config.h posture);
// the Rust twin carries ONE slot per module behind an Rc so the
// handler's ++ and the module's get_counts read the same cell (R2
// single-thread posture — deviation row 17z).
// ==================================================================

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct FileLogStats {
    pub total_events: PegCount, // cc:50 (the ONLY peg; pegs V2 line)
}

/// cc:55-:59 `static const PegInfo fl_pegs[]` — {SUM,"total_events",
/// "total file events"} + END terminator (V2 pins `peg0=total_events
/// help0=total file events type0=1 end1=1`, vectors.txt:4).
pub const FL_PEGS: [PegInfo; 2] = [
    PegInfo { peg_type: CountType::Sum, name: "total_events", help: "total file events" },
    PegInfo { peg_type: CountType::End, name: "", help: "" }, // C: nullptr, nullptr
];

// ==================================================================
// dl_tinit / dl_tterm — cc:67-:70 / cc:72-:75 over the THREAD_LOCAL
// `tlog` slot cc:65. The Rust models the thread slot as ONE shared
// handle (single-thread posture, PLAN R2; the C `tlog` is nulled NOW
// by dl_tterm — the Rust Option take modelsfclose+free; deviation
// row 17z, the stale-pointer posture has no Rust meaning).
// ==================================================================

pub type TlogSlot = Rc<RefCell<Option<TextLog>>>;

/// cc:67-:70 `dl_tinit`: `tlog = TextLog_Init(f_name, 64*K_BYTES,
/// 1*M_BYTES)` — the landed free fn UNEDITED (the ThreadState/
/// NamingConfig/now/engine/sink args are its lifecycle args, the same
/// the 16r textlog replay drives; the harness-side get_main_file
/// witness returns the bare name — the probe's file.log lands in CWD,
/// PLAN R2).
#[allow(clippy::too_many_arguments)]
pub fn dl_tinit(
    slot: &TlogSlot,
    ts: &crate::main::thread::ThreadState,
    conf: &crate::main::thread::NamingConfig,
    engine: &mut LogEngine,
    now: &mut Clock,
    sink: &crate::log::text_log::StdoutSink,
) {
    let tlog = text_log_init(
        LOG_FILE_NAME, TLOG_MAX_BUF, TLOG_MAX_FILE, TLOG_IS_CRITICAL,
        ts, conf, engine, now, sink,
    );
    *slot.borrow_mut() = tlog; // cc:69 assignment (None stays None)
}

/// cc:72-:75 `dl_tterm`: `TextLog_Term(tlog)` — flush + fclose + free
/// (the landed flush chain + the Handle::File drop).
pub fn dl_tterm(slot: &TlogSlot, now: &mut Clock, engine: &mut LogEngine) {
    let mut slot = slot.borrow_mut();
    if let Some(mut tlog) = slot.take() {
        text_log_term(Some(&mut tlog), now, engine);
    }
}

// ==================================================================
// class LogHandler : public DataHandler — cc:81-:92.
//   * ctor `DataHandler(s_name)` cc:84 -> the module_name tag
//   * `handle(DataEvent&, Flow*)` cc:87 -> [`LogHandler::handle`]
//   * private `FileLogConfig config` cc:90 -> held by value
//   * private static `log_file_name(TextLog*, FileContext*)` cc:91
//     -> [`LogHandler::log_file_name`] (the row .o's first T symbol,
//     scratch `nm --defined-only` classification, PLAN §1).
// Deviation row 17z: the `DataEvent&` receiver is INERT in C (unnamed
// arg) and drops from the Rust signature — noted at the handle arm.
// ==================================================================

/// cc:162-:164 `SfIpString ip_str` — ONE reused char buffer for the
/// client/server pair: the SECOND `ntop` overwrites the same buffer
/// (PLAN R3 pin: "one SfIpString reused for the ip pair"); both
/// answers are read BEFORE the next ntop, so the transcript is
/// unaffected — the port's owned Strings normalise that aliasing
/// without changing a byte (deviation note at the call arms).
///
/// The Flow stand-in models the harness `flowz/flow_fwd.h` witness:
/// the NEW17z graft adds `uint16_t client_port/server_port` (flog
/// PLAN §2.1 item 5 <-> real flow.h:586-:587 — the donor witness
/// carried only ip/group/key).
#[derive(Clone, Debug, Default)]
pub struct FlowLite {
    pub client_ip: String, // SfIp::ntop output (vectors: 1.2.3.4)
    pub server_ip: String, // vectors: 5.6.7.8
    pub client_port: u16, // vectors: 1234
    pub server_port: u16, // vectors: 80
}

/// The subscribe-time by-value config + the SHARED stats slot (the
/// handler++ target IS the module's get_counts object — the V7 ladder
/// in vectors.txt:37/:41-:42 only works because they alias).
pub struct LogHandler {
    /// cc:90 by-value copy taken at `new LogHandler(config)` (cc:212);
    /// the fl_ctor copy chain (cc:283-:287) re-signs it per inspector
    /// construction (probe V2b note: one more ctor after each flip
    /// re-arms the handler's own copy).
    pub config: FileLogConfig,
    /// cc:53 fl_stats alias (R2 single-thread posture).
    pub stats: Rc<RefCell<FileLogStats>>,
}

impl LogHandler {
    /// cc:83-:85 `LogHandler(const FileLogConfig& conf) :
    /// DataHandler(s_name), config(conf)` — the base ctor arg lands
    /// `module_name = s_name` at data_bus.h:95 (the W1 tag).
    pub fn new(config: &FileLogConfig, stats: &Rc<RefCell<FileLogStats>>) -> LogHandler {
        LogHandler { config: *config, stats: Rc::clone(stats) }
    }

    /// cc:91 declaration order lands it as the private static.
    /// cc:94-:138 `LogHandler::log_file_name` — the format-quirk
    /// freeze (flog PLAN §1 "the sanitizer … the format quirk to
    /// freeze"; vectors.txt:21-:34 V4c/V5 arms):
    ///   * EMPTY name -> return, NO `[Name: ]` field at all (cc:96-
    ///     :98; vectors.txt:31 shows the line WITHOUT any Name arm);
    ///   * `get_UTF8_fname(&fname_len)` cc:102 then the
    ///     `outbuf != nullptr ? outbuf : name.c_str()` arm cc:103 —
    ///     rides the landed get_utf8_fname (file_lib.rs:1790; None ==
    ///     C null outbuf; same resolution shape as file_event_
    ///     filename, file_lib.rs:2319-:2331);
    ///   * `[Name: ` via TextLog_Puts (cc:106) + `"` via Putc
    ///     (cc:107);
    ///   * per-char C-locale isprint -> verbatim Putc (cc:113);
    ///   * unprintable RUN -> `|` (cc:118), then per byte the
    ///     `%02X`-with-NO-leading-space FIRST / ` %02X` after ladder
    ///     (`add_space` quirk cc:119-:128 — vectors.txt:33 `A|01 02
    ///     7F|B|E9|C` and :34 `tail:|80|`), closing `|` (cc:131);
    ///   * tail `"] "` (cc:135); `snort_free(outbuf)` (cc:136-:137)
    ///     is Rust ownership.
    pub fn log_file_name(log: &mut TextLog, file: &FileInfo, now: &mut Clock, engine: &mut LogEngine) {
        // cc:96 `const std::string& name = file->get_file_name()`
        let name = file.get_file_name();
        if name.is_empty() {
            return; // cc:98-:99 `if (name.empty()) return;`
        }

        // cc:101-:103 size_t fname_len = length(); char* outbuf =
        // get_UTF8_fname(&fname_len); fname = outbuf ? outbuf : raw
        let outbuf = get_utf8_fname(name);
        let fname: &[u8] = match &outbuf {
            Some(u) => u.as_slice(), // (outbuf != nullptr) ? outbuf :
            None => name,           // name.c_str()
        };

        // cc:106-:107 TextLog_Puts(log, "[Name: ") + Putc('"')
        text_log_puts(log, "[Name: ", now, engine);
        log.putc(b'"', now, engine);

        // cc:109-:133 the sanitizer walk (structure-VERBATIM)
        let mut pos = 0usize;
        while pos < fname.len() {
            if c_isprint(fname[pos]) {
                log.putc(fname[pos], now, engine); // cc:113
                pos += 1;
            } else {
                log.putc(b'|', now, engine); // cc:118
                let mut add_space = false; // cc:119
                while pos < fname.len() && !c_isprint(fname[pos]) {
                    if add_space {
                        // cc:121 TextLog_Print(log, " %02X", (uint8_t)
                        // fname[pos]) -- format string VERBATIM, cfmt
                        // %02X (zero-pad 2, UPPERCASE X conv).
                        log.print(" %02X", &[Arg::U(fname[pos] as u64)], now, engine);
                    } else {
                        // cc:124 TextLog_Print(log, "%02X", ...) — the
                        // FIRST byte of a run carries NO leading space
                        // (the pinned quirk); then add_space = true.
                        log.print("%02X", &[Arg::U(fname[pos] as u64)], now, engine);
                        add_space = true;
                    }
                    pos += 1;
                }
                log.putc(b'|', now, engine); // cc:131
            }
        }

        // cc:135 TextLog_Puts(log, "\"] ")
        text_log_puts(log, "\"] ", now, engine);
        // cc:136-:137 `if (outbuf) snort_free(outbuf)` — Rust drop.
    }

    /// cc:140-:196 `handle(DataEvent&, Flow*)` — the emission-order
    /// oracle (flog PLAN §1): opt sys-time arm (cc:142-:151) -> opt
    /// pkt-time arm (cc:153-:160) -> ` %s:%d -> ` + `%s:%d, ` pair
    /// (cc:162-:164) -> get_file_flows NULL EARLY RETURN (cc:166-
    /// :169) -> null current-context EARLY RETURN (cc:171-:174) ->
    /// log_file_name -> `[Verdict: %s] ` VerdictName[verdict] (cc:178)
    /// -> `[Type: %s] ` via the FREE file_type_name (cc:180-:183) ->
    /// conditional `[SHA: %s] ` (cc:185-:187) -> conditional
    /// `[Size: %llu] ` at strict `fsize > 0` (cc:189-:191) -> `"\n"`
    /// (cc:193) -> `fl_stats.total_events++` (cc:195).
    ///
    /// BOTH early-return arms STILL emit the timestamp + ip pair (the
    /// arms run FIRST) — the partial-line quirk frozen by vectors
    /// .txt:21 (three timestamp+pair fragments merged into the NEXT
    /// complete line inside the 64K buffer; probe V4 comment).
    ///
    /// Deviations (row 17z; one `// DEVIATION (row 17z)` note rides
    /// each site):
    ///   * the two clock READS (wall gettimeofday cc:145,
    ///     packet_gettimeofday cc:155) are injected `Option<(i64, u32)>`
    ///     inputs — the Clock-injection idiom (PLAN R1 "Time source
    ///     PIN decision mirrors the landed Rust pattern"); a flag set
    ///     with no injected time renders nothing (the harness pins only
    ///     the pkt arm live, sys arm behind the set-ladder/CFGLOG pair);
    ///   * `flows_present`/`file` model the two C null-return lookups
    ///     (cc:166 / cc:171) — reached for real through landed
    ///     file_flows.rs by the driver;
    ///   * `env` threads what C resolves through the `get_file_config
    ///     ()` singleton chain (file_config.rs:102-:107 doc).
    // C's handle(DataEvent&, Flow*) is 2 args; the seam's injected
    // time/env/lookup inputs widen it — the landed file-level allow
    // precedent rides util.rs:6 (the same seam-arg widening the
    // 17q/17y FileServiceLite arms took).
    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &self,
        log: &mut TextLog,
        flow: &FlowLite,
        flows_present: bool,
        file: Option<&FileInfo>,
        env: &FileEnvLite,
        time_cfg: &TimeCfg,
        sys_now: Option<(i64, u32)>,
        pkt_now: Option<(i64, u32)>,
        now: &mut Clock,
        engine: &mut LogEngine,
    ) {
        // ---- cc:142-:151 the sys-time arm (log_sys_time defaults
        // false — the wall gettimeofday is NEVER read in the pinned
        // V3/V4 arms; the arm stays pinned by the set() ladder + the
        // CFGLOG show pair ONLY, probe header R1).
        if self.config.log_sys_time
            && let Some((sec, usec)) = sys_now
        {
            // DEVIATION (row 17z): gettimeofday -> injected time.
            // cc:146-:147 char timestamp[TIMEBUF_SIZE] (27) +
            // ts_print -> the C-default yyyymmdd=false arm, i.e.
            // the landed ts_print_mmdd (util.rs:129).
            let timestamp = ts_print_mmdd(time_cfg, sec, usec);
            debug_assert!(timestamp.len() < TIMEBUF_SIZE); // util.h:67 buffer pin
            text_log_puts(log, &timestamp, now, engine); // cc:148
            log.print(" ", &[], now, engine); // cc:149
        }

        // ---- cc:153-:160 the pkt-time arm (log_pkt_time defaults ON).
        if self.config.log_pkt_time
            && let Some((sec, usec)) = pkt_now
        {
            // DEVIATION (row 17z): packet_gettimeofday -> injected
            // time (the REAL packet_time_update({1700000000,
            // 500000}) arms the probe pins `sv=1700000000.500000`,
            // vectors.txt:20).
            let timestamp = ts_print_mmdd(time_cfg, sec, usec); // cc:156-:157
            debug_assert!(timestamp.len() < TIMEBUF_SIZE);
            text_log_puts(log, &timestamp, now, engine); // cc:158
            log.print(" ", &[], now, engine); // cc:159
        }

        // ---- cc:162-:164 the ip pair — format strings VERBATIM.
        // DEVIATION (row 17z): the single reused SfIpString (R3) is
        // normalised to owned Strings; byte-ident output either way
        // (each ntop result is consumed before the next call).
        log.print(
            " %s:%d -> ",
            &[Arg::S(Some(flow.client_ip.as_str().into())), Arg::I(flow.client_port as i64)],
            now,
            engine,
        );
        log.print(
            "%s:%d, ",
            &[Arg::S(Some(flow.server_ip.as_str().into())), Arg::I(flow.server_port as i64)],
            now,
            engine,
        );

        // ---- cc:166-:169 `FileFlows* files = FileFlows::get_file_
        // flows(f); if (!files) return;`
        // DEVIATION (row 17z): the two-stage lookup reaches for real
        // through landed file_flows.rs (17q); the seam hands the
        // resolved presence/current pair here.
        if !flows_present {
            return;
        }

        // ---- cc:171-:174 `FileContext* file = files->get_current_
        // file_context(); if (!file) return;`
        // DEVIATION (row 17z) same seam ruling as above.
        let file = match file {
            Some(f) => f,
            None => return,
        };

        // ---- cc:176 log_file_name(tlog, file)
        Self::log_file_name(log, file, now, engine);

        // ---- cc:178 `[Verdict: %s] ` VerdictName[file->verdict] —
        // the global table (file_lib.h:38-:39; the landed VERDICT_NAME
        // at file_lib.rs:62; index 7 == FILE_VERDICT_MAX -> "INVALID",
        // the tail of the vectors' 8-step walk, vectors.txt:21-:30).
        // C indexes unchecked; the Rust slice panics on out-of-range —
        // unreachable for any FileVerdict the enum defines (deviation
        // note row 17z only if a verdict > 7 were ever stored).
        log.print(
            "[Verdict: %s] ",
            &[Arg::S(Some(VERDICT_NAME[file.verdict as usize].into()))],
            now,
            engine,
        );

        // ---- cc:180-:183 `std::string type_name = file_type_name(
        // file->get_file_type())` — the FREE GLOBAL (file_config.cc:80)
        // through the landed file_config.rs:110 (null-conf -> "NA",
        // PLAN R6; conf arm -> the file_lib.rs:915 member, whose
        // CONTINUE/UNKNOWN specials answer both pinned Type arms).
        // DEVIATION (row 17z): the C singleton chain becomes the
        // threaded `env`.
        let type_name = file_config::file_type_name(env, file.get_file_type());
        log.print("[Type: %s] ", &[Arg::S(Some(type_name.as_str().into()))], now, engine);

        // ---- cc:185-:187 conditional `[SHA: %s] `
        // `const uint8_t* sha = file->get_file_sig_sha256(); if (sha)`
        // — UPPERCASE via the landed sha_to_string (file_lib.rs:590;
        // the vectors' `ABAB...` block, vectors.txt:43-:46, PLAN R3).
        if let Some(sha) = file.get_file_sig_sha256() {
            let s = file.sha_to_string(sha);
            log.print("[SHA: %s] ", &[Arg::S(Some(s.as_str().into()))], now, engine);
        }

        // ---- cc:189-:191 conditional `[Size: %llu] ` at strict
        // `fsize > 0` (the skip-at-0 pin: vectors.txt:43 has NO Size
        // field, :44 renders `[Size: 4096] `).
        let fsize = file.get_file_size();
        if fsize > 0 {
            log.print("[Size: %llu] ", &[Arg::U(fsize)], now, engine); // PRIu64
        }

        // ---- cc:193 TextLog_Print(tlog, "\n") — conversion-free
        // format; cfmt copies it byte-ident through the same buffer
        // machine (deviation note row 17z: kept the PRINT call shape
        // rather than a raw write, so the buffer/flush arms differ
        // from C by nothing observable).
        log.print("\n", &[], now, engine);

        // ---- cc:195 fl_stats.total_events++ (the V7 counter arms,
        // vectors.txt:37 pre=17 / :41 now=1 / :42 reset=0).
        self.stats.borrow_mut().total_events += 1;
    }
}

/// C-locale isprint over a (signed) char: 0x20..=0x7E only (0x7F and
/// 0x80..=0xFF NOT printable — the sign rule). The landed private
/// copy lives at file_lib.rs:1741-:1743; promoting it to pub would
/// churn file_lib's pub surface, so the row TU carries its own copy
/// of the three-line rule — same rule the harness's isprint links
/// against libc (deviation row 17z: a DUPLICATED private, not a
/// shared pub).
fn c_isprint(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// text_log.h:74 the `TextLog_Puts` INLINE: `return snort::TextLog_
/// Write(txt, str, strlen(str))` (flog PLAN §0: the inline LOWERS to
/// TextLog_Write -- 5 residues, not 6). The port spells the SAME
/// lowering here (the landed twin publishes `write` with the explicit
/// len, text_log.rs:302; `strlen(str)` == the &str's byte length).
/// Every cc Puts arm (cc:106/:135/:148/:158) routes through this.
fn text_log_puts(log: &mut TextLog, s: &str, now: &mut Clock, engine: &mut LogEngine) -> bool {
    log.write(s, s.len() as i64, now, engine)
}

/// The subscribe seam (cc:212). C registers `new LogHandler(config)`
/// on the intrinsic bus forever (perpetual-subscriber posture,
/// file_cache_share.rs:306-:309). `DataBus::subscribe` itself is the
/// harness W1 witness (stubs.cc NEW17z block; vectors.txt:13
/// `W1 subscribe name=snort eid=23 handler=file_log`) — the Rust
/// seam mirrors MpBusSeam (file_inspect.rs:177-:184) and NEVER runs a
/// real bus (PLAN R4: configure() only REGISTERS; production bus
/// wiring is a later row).
pub trait DataBusSeam {
    fn subscribe(&mut self, publisher: &str, evt: u32, handler_name: &'static str);
}

// ==================================================================
// class FileLog : public Inspector — cc:202-:218 (show body
// cc:220-:224, configure body cc:210-:214).
// ==================================================================

pub struct FileLog {
    /// cc:216 by-value config (the fl_ctor copy, cc:285-:286).
    pub config: FileLogConfig,
    /// the fl_stats alias (module-owned cell).
    pub stats: Rc<RefCell<FileLogStats>>,
}

impl FileLog {
    /// cc:204-:205 `FileLog(const FileLogConfig& conf) : config(conf)`.
    pub fn new(config: &FileLogConfig, stats: &Rc<RefCell<FileLogStats>>) -> FileLog {
        FileLog { config: *config, stats: Rc::clone(stats) }
    }

    /// cc:220-:224 `show(const SnortConfig*) const` — the REAL
    /// ConfigLogger pair (landed messages.rs:444; the V2b CFGLOG
    /// transcripts vectors.txt:5-:6 / :8-:9 / :11-:12; the conf
    /// receiver is unnamed/inert in C and drops).
    pub fn show(&self, engine: &mut LogEngine) {
        crate::log::messages::ConfigLogger::log_flag(engine, "log_pkt_time", self.config.log_pkt_time, false); // cc:222
        crate::log::messages::ConfigLogger::log_flag(engine, "log_sys_time", self.config.log_sys_time, false); // cc:223
    }

    /// cc:210-:214 `configure(SnortConfig*)` — the one statement +
    /// `return true` (the W1 pin `V3_sub ret=1 calls=0->1 stashed=1`,
    /// vectors.txt:14). The SnortConfig receiver is inert and drops.
    pub fn configure(&self, bus: &mut dyn DataBusSeam) -> bool {
        // cc:212 DataBus::subscribe(intrinsic_pub_key, IntrinsicEvent
        // Ids::FILE_VERDICT, new LogHandler(config)) — the allocation
        // hand-off is modelled BY NAME (the 17t MpBusSeam ruling):
        // handler_name == s_name == the C module_name the witness
        // prints. The stats alias is handed to the driver-side
        // handler build (FileLogModule::subscribe).
        bus.subscribe(INTRINSIC_PUB_KEY, INTRINSIC_EVENT_ID_FILE_VERDICT, MODULE_NAME);
        true
    }
}

// ==================================================================
// class FileLogModule : public Module — cc:241-:260; the set body
// cc:262-:271 is the two-arm ladder with the UNCONDITIONAL `return
// true` (cc:270 — an unmatched name is NOT an error; vectors.txt:7
// `V2b_set non=1 ret=111`).
// ==================================================================

/// cc:230-:239 `static const Parameter fl_params[]` — the frozen
/// 2-arm table + PT_MAX terminator (V2 pins `p0=log_pkt_time d0=true
/// pt0=3 p1=log_sys_time d1=false pt1=3 last_null=1 ptmax=21`;
/// PT_BOOL -> PtBool discriminant 3, PT_MAX -> PtMax 21). C's
/// `help` slot strings ("log the packet time when event generated" /
/// "log the system time when event generated") have NO slot in the
/// landed Parameter struct (parameter.rs:36-:40, help deferred with
/// the option-parsing layer — pinned here in this comment, deviation
/// row 17z note).
pub const FL_PARAMS: [Parameter; 3] = [
    Parameter {
        name: Some("log_pkt_time"), // cc:231
        ptype: PtType::PtBool,
        deflt: Some("true"), // cc:232 — defaults ON
    },
    Parameter {
        name: Some("log_sys_time"), // cc:234
        ptype: PtType::PtBool,
        deflt: Some("false"), // cc:235 — defaults OFF
    },
    Parameter {
        name: None, // cc:238 `{ nullptr, Parameter::PT_MAX, ... }`
        ptype: PtType::PtMax,
        deflt: None,
    },
];

pub struct FileLogModule {
    /// cc:259 `public: FileLogConfig config` — the fl_ctor copy
    /// source (cc:283-:287 static_cast + copy).
    pub config: FileLogConfig,
    /// cc:53 the THREAD_LOCAL fl_stats the pegs read; the probe reads
    /// it through `mod->get_counts()` (V7 arms).
    pub counts: Rc<RefCell<FileLogStats>>,
}

impl Default for FileLogModule {
    fn default() -> Self {
        Self::new()
    }
}

impl FileLogModule {
    /// cc:243-:245 `FileLogModule() : Module(s_name, s_help,
    /// fl_params)` — the landed Module-layer home has no Rust Module
    /// struct yet (framework/ has no module.rs; the module-manager
    /// layer is a later row), so the (name, help, params) triple is
    /// pinned as THIS type's consts (MODULE_NAME / MODULE_HELP /
    /// FL_PARAMS) — deviation row 17z: module-base plumbing stays
    /// harness-side (REAL module.o answers it there, PLAN §0).
    pub fn new() -> FileLogModule {
        FileLogModule {
            config: FileLogConfig::default(), // cc:42-:46 defaults
            counts: Rc::new(RefCell::new(FileLogStats::default())),
        }
    }

    /// cc:247-:248 `get_pegs() const -> fl_pegs`.
    pub fn get_pegs(&self) -> &'static [PegInfo; 2] {
        &FL_PEGS
    }

    /// cc:250-:251 `get_counts() const -> (PegCount*)&fl_stats` — the
    /// reinterpret_cast over the one-peg struct; the Rust hands the
    /// cell itself (the alias IS the cast's point).
    pub fn get_counts(&self) -> &Rc<RefCell<FileLogStats>> {
        &self.counts
    }

    /// cc:262-:271 `set(const char*, Value& v, SnortConfig*)` — the
    /// two-arm `v.is()` ladder + `v.get_bool()` (landed value.rs:181
    /// /:196); NOTE the unconditional `return true` (cc:270):
    /// `mod->set("bogus_name", ...)` answers TRUE (V2b `ret=111`).
    /// The name + conf receivers are inert in C and drop.
    pub fn set(&mut self, v: &Value) -> bool {
        if v.is("log_pkt_time") {
            self.config.log_pkt_time = v.get_bool(); // cc:263-:264
        } else if v.is("log_sys_time") {
            self.config.log_sys_time = v.get_bool(); // cc:266-:267
        }
        true // cc:270
    }

    /// cc:255-:256 `get_usage() const -> INSPECT`. The Usage enum has
    /// no landed Rust home yet (module layer seam; PLAN §3 keeps the
    /// shape a probe-side pin) — C INSPECT = 2 rides vectors.txt:4
    /// `usage=2` as a const pin.
    pub const C_USAGE_INSPECT: u32 = 2;

    /// api slot fl_ctor (cc:283-:287): static_cast the module, COPY
    /// its config into the inspector.
    pub fn make_inspector(&self) -> FileLog {
        FileLog::new(&self.config, &self.counts)
    }

    /// api slot mod_ctor -> this + fl_ctor composed: the configure()
    /// subscribe builds the handler over THIS config + the SHARED
    /// stats cell (the C handler's ++ target is the TLS the module
    /// counts — the V7 alias, vectors.txt:37).
    pub fn subscribe(&self, bus: &mut dyn DataBusSeam) -> LogHandler {
        bus.subscribe(INTRINSIC_PUB_KEY, INTRINSIC_EVENT_ID_FILE_VERDICT, MODULE_NAME);
        LogHandler::new(&self.config, &self.counts)
    }
}

// ==================================================================
// the api record + registry (cc:294-:329). The record rides the
// landed InspectApiRecord shape (file_inspect.rs:486-:508, the 17w
// precedent: fn-pointer slots -> presence bools; `size` probe-pinned
// 152, never size_of).
// ==================================================================

/// cc:294-:320 `static const InspectApi fl_api` — the const-record
/// pin (flog PLAN §3 row 9: "port as one const-record pin, OR keep
/// probe-side C-frozen; fields ride vectors.txt V1"). V1 reads every
/// field: `V1_registry n=2 name=file_log help=log file event to
/// file.log size=152 apiver=1900549 plugtype=1 itype=0 pbits=0
/// second=file_inspect third_null=1` + V1_statics slot liveness
/// `tinit=1 tterm=1 ctor=1 dtor=1 pinit=0 pterm=0 ssn=0 reset=0`
/// (vectors.txt:2-:3).
pub const FL_API: InspectApiRecord = InspectApiRecord {
    ptype: PT_INSPECTOR, // cc:297
    size: PROBE_SIZEOF_INSPECT_API, // sizeof(InspectApi)==152 (V1 size=152)
    api_version: INSAPI_VERSION, // (29 << 16) | 5 == 1900549 (V1 apiver)
    version: 0, // cc:300 BaseApi version slot
    features: API_RESERVED, // 0
    options: API_OPTIONS, // 0
    name: MODULE_NAME, // cc:304 s_name "file_log"
    help: MODULE_HELP, // cc:305 s_help
    itype: IT_PASSIVE, // cc:309 (config-only inspector; PLAN 17z)
    proto_bits: PROTO_BIT__NONE, // cc:310
    buffers: None, // cc:311 `nullptr, // buffers`
    // cc:312 `nullptr, // service` — the record's service slot is a
    // &'static str in the landed shape (finspect carried "file");
    // the empty string is the stand-in for the nullptr (deviation
    // row 17z: Option<()> would fork the record shape the 17w
    // vectors already freeze).
    service: "",
    // cc:313-:314 `nullptr, // pinit` + `nullptr, // pterm`
    pinit: false,
    pterm: false,
    // cc:315-:316 `dl_tinit,` `dl_tterm,` (free fns, dl_ arm)
    tinit: true,
    tterm: true,
    // cc:317-:318 `fl_ctor,` `fl_dtor,`
    ctor: true,
    dtor: true,
    // cc:319-:320 `nullptr, // ssn` + `nullptr // reset`
    ssn: false,
    reset: false,
};

/// cc:322-:329: `extern const BaseApi* sin_file_flow;` (resolves
/// file_inspect.cc:175 <-> the landed SIN_FILE_FLOW, file_inspect.rs:
/// :515) and `const BaseApi* sin_file[] = { &fl_api.base,
/// sin_file_flow, nullptr }` — THE row's only non-static data export.
/// Stays a DOC-SEAM (flog PLAN §3 row 6: "add the pin, no new
/// record" — the file_inspect.rs:511-:512 comment already names this
/// consumer): the readback below mirrors V1's count/name walk ONLY.
pub mod sin_file {
    use super::super::file_inspect::SIN_FILE_FLOW;
    use super::FL_API;

    /// the null-terminated list length V1 counts (`n=2`).
    pub fn count() -> usize {
        2
    }

    /// V1 readback: `[0]=file_log [1]=file_inspect [2]=nullptr`
    /// (`second=file_inspect third_null=1`, vectors.txt:2).
    pub fn names() -> [Option<&'static str>; 3] {
        [Some(FL_API.name), Some(SIN_FILE_FLOW.name), None]
    }
}

// ==================================================================
// frozen-arm unit tests (row 17z). The BYTES transcript oracle stays
// in tools/flog_harness/vectors.txt (md5-pinned, NEVER edit) + the
// C gate; these tests re-derive the SAME pinned facts through this
// module's arms with the landed REAL twins driving the buffers — the
// real-TU-parity-as-witness pattern (flog PLAN §3).
// ==================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_api::file_lib::{SNORT_FILE_TYPE_CONTINUE, SNORT_FILE_TYPE_UNKNOWN};
    use crate::file_api::file_lib::{FileConfigLite, FileEnvLite};
    use crate::main::thread::{NamingConfig, SThreadType, ThreadState};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct NullBus {
        calls: u32,
        last: Option<(String, u32, &'static str)>,
    }
    impl NullBus {
        fn new() -> NullBus {
            NullBus { calls: 0, last: None }
        }
    }
    impl DataBusSeam for NullBus {
        fn subscribe(&mut self, publisher: &str, evt: u32, handler_name: &'static str) {
            self.calls += 1;
            self.last = Some((publisher.to_string(), evt, handler_name));
        }
    }

    /// runtime view of the compile-time slot-liveness const pin (the
    /// test calls THIS so the frozen V1_statics line stays a named
    /// test arm; the const block above already failed the build
    /// should it break).
    fn assert_slot_liveness() {
        let liveness = [
            FL_API.tinit, FL_API.tterm, FL_API.ctor, FL_API.dtor,
            FL_API.pinit, FL_API.pterm, FL_API.ssn, FL_API.reset,
        ];
        assert_eq!(liveness, [true, true, true, true, false, false, false, false]);
    }

    /// A live TextLog over a unique tmp file (the probe windows):
    /// ThreadState=Main + NamingConfig{log_dir: tmp, id_zero: true}
    /// so get_main_file answers exactly `<tmp>/file.log` (the C stub
    /// get_main_file returned the bare name and the probe ran in the
    /// harness CWD — same posture, sandboxed to the scratch dir).
    fn window(tag: &str) -> (TextLog, std::path::PathBuf, Clock, LogEngine) {
        let dir = std::env::temp_dir().join(format!("row17z_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ts = ThreadState::default();
        ts.set_thread_type(SThreadType::Main);
        let conf = NamingConfig { log_dir: dir.to_str().unwrap().to_string(), id_zero: true, ..Default::default() };
        let mut engine = LogEngine::default();
        let mut now: Clock = Box::new(|| 1_700_000_000);
        let sink = Rc::new(RefCell::new(Vec::new()));
        let tlog = text_log_init(
            LOG_FILE_NAME, TLOG_MAX_BUF, TLOG_MAX_FILE, TLOG_IS_CRITICAL,
            &ts, &conf, &mut engine, &mut now, &sink,
        )
        .unwrap();
        (tlog, dir, now, engine)
    }

    // vectors.txt :13-:14  W1 subscribe + V3_sub (the W1 witness mirror)
    #[test]
    fn row17z_w1_subscribe_mirror() {
        let mut bus = NullBus::new();
        assert_eq!(bus.calls, 0); // V3 `calls=0->1`
        let m = FileLogModule::new();
        let insp = m.make_inspector();
        let ret = insp.configure(&mut bus);
        assert!(ret); // V3_sub ret=1
        assert_eq!(bus.calls, 1);
        let (key, eid, tag) = bus.last.clone().unwrap();
        assert_eq!(key, "snort"); // W1 name=snort (intrinsic_pub_key)
        assert_eq!(key, INTRINSIC_PUB_KEY);
        assert_eq!(eid, 23); // W1 eid=23 (IntrinsicEventIds::FILE_VERDICT)
        assert_eq!(eid, INTRINSIC_EVENT_ID_FILE_VERDICT);
        assert_eq!(tag, "file_log"); // W1 handler=file_log (module_name)
    }

    // vectors.txt :2-:3    V1_registry + V1_statics
    #[test]
    fn row17z_v1_record_statics() {
        assert_eq!(FL_API.name, "file_log");
        assert_eq!(FL_API.help, "log file event to file.log");
        assert_eq!(FL_API.size, 152); // size=152 (probe pin; never size_of)
        assert_eq!(FL_API.api_version, 1900549); // apiver=1900549
        assert_eq!(FL_API.ptype, 1); // plugtype=1
        assert_eq!(FL_API.itype, 0); // itype=0
        assert_eq!(FL_API.proto_bits, 0); // pbits=0
        // slot-liveness pins ride the const block below (V1_statics).
        assert_slot_liveness();
        // constant pins at compile time (the file_policy.rs:55
        // `const _: () = assert!` precedent -- clippy
        // assertions_on_constants stays clean):
        //     tb=27  buf=65536  file=1048576   (vectors.txt :3)
        sizeof_overlaps(); // pc8=1 overlap REAL here; see fn doc
        // registry (second=file_inspect third_null=1; n=2)
        assert_eq!(sin_file::count(), 2);
        assert_eq!(sin_file::names(), [Some("file_log"), Some("file_inspect"), None]);
    }

    // vectors.txt :3       V1_statics pc8=1 -- the overlaps REAL on
    // the Rust side only (PegCount == u64 == 8). PegInfo's C 24 and
    // sizeof(InspectApi) 152 vs BaseApi 112 (api_sz_ge=1) stay C-side
    // probe pins; the Rust shapes differ BY DESIGN and no frozen
    // vector reads a Rust size (file_policy.rs:9-:14 rule). mfpf=128
    // is the FileConfig readback (file_config domain, 17u).
    fn sizeof_overlaps() {
        assert_eq!(std::mem::size_of::<PegCount>(), 8); // pc8=1
        assert_eq!(FL_PEGS.len(), 2); // terminator live
        assert_eq!(FL_PARAMS.len(), 3);
    }

    // vectors.txt :4       V2_params (params table, pegs, usage)
    #[test]
    fn row17z_v2_params_pegs() {
        let p = FL_PARAMS;
        assert_eq!(p[0].name, Some("log_pkt_time")); // p0
        assert_eq!(p[0].deflt, Some("true")); // d0
        assert_eq!(p[0].ptype, PtType::PtBool); // pt0=3
        assert_eq!(p[1].name, Some("log_sys_time")); // p1
        assert_eq!(p[1].deflt, Some("false")); // d1
        assert_eq!(p[1].ptype, PtType::PtBool); // pt1=3
        assert_eq!(p[2].name, None); // last_null=1
        assert_eq!(p[2].ptype, PtType::PtMax); // ptmax=21
        assert_eq!(PtType::PtBool as u32, 3);
        assert_eq!(PtType::PtMax as u32, 21);

        let m = FileLogModule::new();
        // ctor defaults (cc:43-:44): pkt ON, sys OFF
        assert_eq!(m.config, FileLogConfig { log_sys_time: false, log_pkt_time: true });
        let pegs = m.get_pegs();
        assert_eq!(pegs[0].name, "total_events"); // peg0
        assert_eq!(pegs[0].help, "total file events"); // help0
        assert_eq!(pegs[0].peg_type as u32, 1); // type0=1 (SUM)
        assert_eq!(pegs[1].peg_type, CountType::End); // end1=1
        assert_eq!(FileLogModule::C_USAGE_INSPECT, 2); // usage=2
        assert_eq!(m.get_counts().borrow().total_events, 0); // counts=1 live
    }

    // vectors.txt :5-:12   the CFGLOG show pair + V2b set ladder
    #[test]
    fn row17z_v2b_set_ladder_show() {
        static PKT_P: Parameter = Parameter { name: Some("log_pkt_time"), ptype: PtType::PtBool, deflt: Some("true") };
        static SYS_P: Parameter = Parameter { name: Some("log_sys_time"), ptype: PtType::PtBool, deflt: Some("false") };
        static BOGUS_P: Parameter = Parameter { name: Some("bogus_name"), ptype: PtType::PtBool, deflt: Some("false") };

        fn bool_value(b: bool, p: &'static Parameter) -> Value {
            let mut v = Value::from_bool(b); // C Value v(true) ctor
            v.set_param(p); // C v.set(&pp)
            v
        }

        // the LIVE module (defaults) -> show pair :5-:6
        let mut m = FileLogModule::new();
        let mut e = LogEngine::default();
        m.make_inspector().show(&mut e);
        let tr = e.transcript();
        // ConfigLogger %*s width 25 right-align ("log_pkt_time" len 12
        // -> 13 leading spaces); vectors shows the witness prefix
        // "CFGLOG" + probe padding, the SUFFixed part is the pin:
        assert!(tr.ends_with("             log_pkt_time: enabled\n             log_sys_time: disabled\n"), "{tr}");

        // flip arms :7 V2b_set non=1 ret=111 (bogus returns TRUE too)
        let a = m.set(&bool_value(true, &SYS_P));
        let b = m.set(&bool_value(false, &PKT_P));
        let c = m.set(&bool_value(true, &BOGUS_P));
        assert_eq!((a, b, c), (true, true, true)); // ret=111
        assert_eq!(m.config, FileLogConfig { log_sys_time: true, log_pkt_time: false });

        // the flip's re-signed inspector (probe: one more ctor after
        // each flip re-signs) -> show pair :8-:9
        let mut e2 = LogEngine::default();
        m.make_inspector().show(&mut e2);
        let tr2 = e2.transcript();
        assert!(tr2.ends_with("             log_pkt_time: disabled\n             log_sys_time: enabled\n"), "{tr2}");

        // back to defaults (V2b_back :11-:12)
        m.set(&bool_value(false, &SYS_P));
        m.set(&bool_value(true, &PKT_P));
        assert_eq!(m.config, FileLogConfig { log_sys_time: false, log_pkt_time: true });
        let mut e3 = LogEngine::default();
        m.make_inspector().show(&mut e3);
        assert_eq!(e3.transcript(), e.transcript()); // :11-:12 == :5-:6
    }

    // vectors.txt :20-:30  V4c full-line arm + VerdictName walk x8
    #[test]
    fn row17z_v4_handle_full_line_and_verdict_walk() {
        // the landed VERDICT_NAME pair-checks the walk end (cc:178).
        assert_eq!(
            VERDICT_NAME,
            ["Unknown", "Log", "Stop", "Block", "Reset", "Pending", "Stop Capture", "INVALID"]
        );

        let (mut log, dir, mut now, mut engine) = window("v4");
        let stats = Rc::new(RefCell::new(FileLogStats::default()));
        let handler = LogHandler::new(&FileLogConfig::default(), &stats);
        let flow = FlowLite {
            client_ip: "1.2.3.4".into(),
            server_ip: "5.6.7.8".into(),
            client_port: 1234,
            server_port: 80,
        };
        let time_cfg = TimeCfg::default(); // shim conf: thiszone 0 / utc off / year off
        let pkt_tv = (1_700_000_000i64, 500_000u32); // the R1 pinned clock (vectors :20)

        let env = FileEnvLite {
            file_config: Some(Rc::new(RefCell::new(FileConfigLite::default()))),
            ..FileEnvLite::default()
        };

        let mut info = FileInfo {
            file_name: b"hello.txt".to_vec(), // set_file_name("hello.txt", 9)
            ..FileInfo::default()
        };

        // one full line (verdict 1 = Log; CONTINUE type default) --
        // vectors.txt:22 verbatim:
        let full = "11/14-22:13:20.500000  1.2.3.4:1234 -> 5.6.7.8:80, [Name: \"hello.txt\"] [Verdict: Log] [Type: Undecided file type, continue...] ";
        info.verdict = 1; // FILE_VERDICT_LOG (probe :222-:223 walk arm v=1)
        handler.handle(&mut log, &flow, true, Some(&info), &env, &time_cfg, None, Some(pkt_tv), &mut now, &mut engine);
        assert_eq!(stats.borrow().total_events, 1); // cc:195 counter

        // both early-return arms (no flows / flows-but-null ctx):
        // timestamp + ip pair STILL emitted (cc:142-:164 run first),
        // counter NOT touched — the partial-line merge quirk that
        // builds vectors.txt:21's triple-fragment line.
        handler.handle(&mut log, &flow, false, None, &env, &time_cfg, None, Some(pkt_tv), &mut now, &mut engine);
        handler.handle(&mut log, &flow, true, None, &env, &time_cfg, None, Some(pkt_tv), &mut now, &mut engine);
        assert_eq!(stats.borrow().total_events, 1);

        // cc:178 indexes VerdictName[file->verdict] — every walked
        // index (probe v=0..7 loop, the INVALID tail rides index 7 =
        // FILE_VERDICT_MAX) answers through the landed table:
        for v in 0..=7u32 {
            if let Some(i2) = VERDICT_NAME.get(v as usize) {
                assert!(!i2.is_empty());
            } else {
                panic!("verdict index {v} must be in the landed table");
            }
        }
        assert_eq!(VERDICT_NAME[0], "Unknown");
        assert_eq!(VERDICT_NAME[7], "INVALID"); // FILE_VERDICT_MAX row

        // Type arms (vectors :29-:30): CONTINUE -> "Undecided file
        // type, continue..." / UNKNOWN -> "Unknown file type, done"
        info.set_file_type(SNORT_FILE_TYPE_UNKNOWN as u64);
        assert_eq!(file_config::file_type_name(&env, info.get_file_type()), "Unknown file type, done");
        info.set_file_type(SNORT_FILE_TYPE_CONTINUE as u64);
        assert_eq!(file_config::file_type_name(&env, info.get_file_type()), "Undecided file type, continue...");

        text_log_term(Some(&mut log), &mut now, &mut engine); // dl_tterm + flush
        let bytes = std::fs::read(dir.join(LOG_FILE_NAME)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(text.lines().next().unwrap(), full); // line 1 == vectors :22
        // the two early-arm fragments merged with NO newline between
        // them (the buffer quirk frozen at vectors.txt:21):
        assert!(text.contains("11/14-22:13:20.500000  1.2.3.4:1234 -> 5.6.7.8:80, 11/14-22:13:20.500000  1.2.3.4:1234 -> 5.6.7.8:80, "));
        assert_eq!(text.split('\n').count(), 2); // one full line + trailing flush fragment
        assert_eq!(stats.borrow().total_events, 1); // counter unchanged by early arms
    }

    // vectors.txt :31-:34  sanitizer arms (empty / "aZ~ " / mixed run /
    //                      single-byte tail run)
    #[test]
    fn row17z_sanitizer_arms() {
        // freeze the RENDERER output as [Name: "..."] field strings
        // through the real TextLog (same field bytes, flushed by term).
        fn name_field(file_name: &[u8]) -> String {
            let (mut log, dir, mut now, mut engine) = window(&format!("san{}", file_name.len()));
            let info = FileInfo {
                file_name: file_name.to_vec(),
                ..FileInfo::default()
            };
            LogHandler::log_file_name(&mut log, &info, &mut now, &mut engine);
            text_log_term(Some(&mut log), &mut now, &mut engine);
            let out = std::fs::read_to_string(dir.join(LOG_FILE_NAME)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            out
        }

        // :31 empty name -> NO [Name:] field AT ALL (cc:96-:98 early)
        assert_eq!(name_field(b""), "");
        // :32 printable incl. space
        assert_eq!(name_field(b"aZ~ "), "[Name: \"aZ~ \"] ");
        // :33 mixed runs: A | 01 02 7F | B | E9 | C -- the add_space
        // quirk: the FIRST byte of each run has NO leading space
        let mixed: Vec<u8> = vec![b'A', 0x01, 0x02, 0x7F, b'B', 0xE9, b'C'];
        assert_eq!(name_field(&mixed), "[Name: \"A|01 02 7F|B|E9|C\"] ");
        // :34 single-byte tail run ("tail:" + 0x80)
        let tail: Vec<u8> = [b"tail:", &[0x80u8][..]].concat();
        assert_eq!(name_field(&tail), "[Name: \"tail:|80|\"] ");

        // the C-locale isprint edges == the landed rule (file_lib.
        // rs:1741-:1743): 0x20/0x7E printable; 0x7F/0x80 NOT.
        assert!(c_isprint(0x20));
        assert!(c_isprint(0x7E));
        assert!(!c_isprint(0x7F));
        assert!(!c_isprint(0x80));
    }

    // vectors.txt :43-:46  SHA presence (UPPERCASE, no Size at 0) +
    // Size present arm -- through the landed file_lib pair directly.
    #[test]
    fn row17z_sha_size_arms() {
        let info = FileInfo::default();
        let digest: [u8; 32] = [0xAB; 32]; // probe memset(0xAB)
        // cc:185-:187 -- UPPERCASE (R3/file_lib.rs:590 conv[]):
        assert_eq!(info.sha_to_string(&digest), "AB".repeat(32));
        // null sha -> NO field (C null guard; the landed Option models):
        assert!(FileInfo::default().get_file_sig_sha256().is_none());
        // Size skip-at-0 pin (cc:189-:191 strict `> 0`):
        assert_eq!(FileInfo::default().get_file_size(), 0); // vectors :43 has NO [Size:]
        let mut info = FileInfo::default();
        info.set_file_size(4096);
        assert_eq!(info.get_file_size(), 4096); // vectors :44 `[Size: 4096] `
    }

    // vectors.txt :35/:47/:49 window byte/line facts are the C gate's
    // pin; the W2 counter shape that rides them (V7 pre=17/post=0/
    // again=1/reset=0, vectors.txt:37/:41-:42) is mirrored here: the
    // handler's++, the module read, the reset.
    #[test]
    fn row17z_w2_counter_ladder() {
        let m = FileLogModule::new();
        let h = m.subscribe(&mut NullBus::new());
        assert!(Rc::ptr_eq(m.get_counts(), &h.stats)); // the cc:53/cc:250 alias
        h.stats.borrow_mut().total_events += 17; // 17 handle()s in window 1
        assert_eq!(m.get_counts().borrow().total_events, 17); // V7 pre=17
        *m.get_counts().borrow_mut() = FileLogStats::default(); // the SUM drain (module.o sum/reset arms)
        assert_eq!(m.get_counts().borrow().total_events, 0); // V7 post=0 / reset=0
        h.stats.borrow_mut().total_events += 1; // V7 again -> now=1
        assert_eq!(m.get_counts().borrow().total_events, 1); // V7_again now=1
    }
}
