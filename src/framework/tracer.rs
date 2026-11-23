//! Flat, cite-heavy literal port of the chapter-19 LAST row 22b pair:
//! `framework/tracer.cc` 73 L (ground truth @ fe29cbe: md5
//! `9ee6b2ee33c4c98144f6a575891d1679`) + `framework/tracer.h` 125 L (md5
//! `98d53205a5ddaff48ba5c304d0658931`) = 198 L — THE PT_TRACE TraceLoggerPlug
//! / TraceLogApi plugin-API pair. Naming law (the frozen misc9 :461 landmine
//! greps the literal `struct Tr` + `acer` (the split token) over src/ —
//! NEVER edit the script): the names ride the C names VERBATIM
//! (TraceLoggerPlug / TraceLogApi — neither carries the killer substring; a
//! bare `pub struct Tr` + `acer...` name DIES at that landmine).
//!
//! THE h HALF (the plugin-API vocabulary, tracer.h): TRACE_LOGAPI_VERSION
//! h :33 = ((BASE_API_VERSION << 16) | 2) — BASE_API_VERSION REUSE-CITED from
//! framework/codec.rs:419 (the sanctioned cross-TU const-dup posture,
//! file_inspect.rs:88 twin); TRACER_FLAG__RESERVED h :35; the abstract
//! TraceLoggerPlug h :43-:110 (pure log() h :49 -> the house trait posture,
//! framework/module.rs ModuleVirt precedent; the set/get pairs; the
//! set_thread_type(char) P/C/O-default-O switch h :79-:92 REUSE-citing
//! main/thread.rs:19 SThreadType — NEVER a second thread-type enum); the two
//! typedefs TraceLogNewFunc/TraceLogDelFunc h :112-:113 land as presence
//! bools (the landed no-fn-pointer posture, codec.rs:457 law); `struct
//! TraceLogApi` h :115-:121 over the BaseApi head (the record-fold posture:
//! codec.rs CodecApiRecord :448 / file_inspect.rs InspectApiRecord :486 —
//! "BaseApi is the record's prefix by construction", NEVER a forked BaseApi
//! struct).
//!
//! THE cc HALF (two methods, tracer.cc): print_ntuple :30-:61 (the
//! ntuple/null/is_valid guard :32; SfIpString + ntop :35-:42 — the char[46]
//! buffer lands as owned Strings, the file_log.rs:233-:236 deviation face,
//! REUSE-CITING the ONE landed ntop home sfip/sf_ip.rs:746 (one-home law; its
//! test_features=false v6 arm was ALIGNED to the glibc/C face by this row —
//! see KNOWN DEVIATIONS.md row 22b, fix-forward rider, NEVER a second ntop);
//! the TCP|UDP port GATE :44-:48 REUSE-CITING the landed PROTO_BIT__TCP/UDP
//! consts detection/rtn_checks.rs:26-:27; the stream face :50-:51; THE PKTH
//! READS :52/:54-:55 — address_space_id + the tenant_id!=0 gate — whose REAL
//! provider fields belong to row 20 (the seam ledger, NEXT.md :837-:840):
//! this row models the harness-extension DECL face as the row-scoped
//! TracePkthLite, a SYNTHETIC carrier, NEVER ABI truth); print_timestamp
//! :63-:72 (the :69 `ts_print(nullptr, ts)` default-yyyymmdd=false arm —
//! REUSE-CITING the landed utils/util.rs:129 ts_print_mmdd home + the TIMEBUF
//! debug_assert posture file_log.rs:417; the C nullptr arm pulls the CLOCK
//! INTERNALLY util.cc:146-:152 — the Rust seam takes the time explicitly,
//! deviation row 22b).
//!
//! The C-ABI layout facts (sizeof(BaseApi)=64 / sizeof(TraceLogApi)=88, the
//! BaseApi-head-of-every-plugin-api face base_api.h :74) land as PROBE-pin
//! consts (the harness vectors_faceA SIZES line — NEVER Rust size_of: the C
//! struct layout is the fact, the Rust mirror needs no matching layout).

use crate::detection::rtn_checks::{IpApiLite, PROTO_BIT__TCP, PROTO_BIT__UDP};
use crate::framework::codec::BASE_API_VERSION;
use crate::framework::codec::ip_protocol::IpProtocol;
use crate::main::thread::SThreadType;
use crate::utils::util::{TimeCfg, ts_print_mmdd};

// ---- framework/base_api.h + tracer.h plugin-API vocabulary ----

/// base_api.h:52-:63 enum PlugType — PT_TRACE = 10 (the 11th enumerator; the
/// ordinal the harness vectors pin `pt_trace=10`; the APIStruct head face).
pub const PT_TRACE: u32 = 10; // the enum walk face-pinned by the 22b harness vectors (APIStruct head=10)
/// tracer.h:33 `#define TRACE_LOGAPI_VERSION ((BASE_API_VERSION << 16) | 2)`.
/// The harness vectors pin `logapi=1900546` == (29 << 16) | 2 (the
/// CDAPI_VERSION/INSAPI_VERSION arithmetic posture, codec.rs:422 /
/// file_inspect.rs:91).
pub const TRACE_LOGAPI_VERSION: u32 = (BASE_API_VERSION << 16) | 2;
/// tracer.h:35 `#define TRACER_FLAG__RESERVED 0x0` (the record flags slot;
/// the API_RESERVED posture base_api.h:48 with the h-own cite).
pub const TRACER_FLAG__RESERVED: u32 = 0;
/// sizeof(BaseApi) == 64 — the probe face (harness vectors_faceA SIZES line
/// `base=64`); PROBE_SIZEOF posture (finspect precedents), NEVER size_of.
pub const PROBE_SIZEOF_BASE_API: u32 = 64;
/// sizeof(TraceLogApi) == 88 (`tracelogapi=88`). base_api.h :74: "BaseApi
/// must be the prefix (ie 1st member) of all plugin api" — the vectors
/// head=10 face OBSERVES the prefix at the C byte level (NEVER reproducible
/// through a Rust layout; the const is the C-ABI fact the mirror cites).
pub const PROBE_SIZEOF_TRACE_LOG_API: u32 = 88;

/// The TraceLogApi record (tracer.h:115-:121 over BaseApi base_api.h:74-:87).
/// The record-fold posture (codec.rs:448 / file_inspect.rs:486): BaseApi is
/// the record's prefix BY CONSTRUCTION of the C struct — the Rust twin
/// states the field values directly (the fn-pointer slots ride presence
/// bools, the codec.rs:457 no-fn-pointer law; the :119/:120 typedef slots
/// likewise; the `unsigned flags` h :118 is a plain u32 here, h-own).
#[derive(Debug)]
pub struct TraceLogApiRecord {
    pub ptype: u32,           // BaseApi PlugType (base_api.h:76)
    pub size: u32,            // sizeof(plugin-api) (:77) — probe pin, NEVER size_of
    pub api_version: u32,     // (BASE_API_VERSION << 16) | 2 (:78)
    pub version: u32,         // (:79)
    pub features: u64,        // any PLUGIN_* (:80)
    pub options: u32,         // :81 const char* options — the API_OPTIONS u32 posture (codec.rs:441)
    pub name: &'static str,   // :82
    pub help: &'static str,   // :83
    pub mod_ctor: bool,       // ModNewFunc (:84) presence face
    pub mod_dtor: bool,       // ModDelFunc (:85)
    pub flags: u32,           // :118 `unsigned flags` (TRACER_FLAG__RESERVED face)
    pub new_fn: bool,         // :119 TraceLogNewFunc (h:112 typedef) presence — NEVER a Rust fn-ptr
    pub del_fn: bool,         // :120 TraceLogDelFunc (h:113 typedef) presence
}

// ---- tracer.h TraceLoggerPlug (h :43-:110) ----

/// h :49 the PURE virtual: `virtual void log(const char* msg, const char*
/// name, uint8_t level, const char* trace_option, const Packet*) = 0`. The
/// house abstract-base posture (framework/module.rs:138 ModuleVirt law: C
/// virtuals -> an explicit trait). The `const Packet*` tail rides the row's
/// read-face Option (below); the PT_TRACE loader/consumer NEVER lands before
/// the row-20/21 plugin face — honest LEFT-OPEN provider, NEVER invented.
pub trait TraceLogPlugVirt {
    fn log(&self, msg: &str, name: &str, level: u8, trace_option: &str, pkt: Option<&TracePacketReadFace>);
}

/// The SYNTHETIC pkth read-face (tracer.cc :52/:54-:55). The REAL provider is
/// the DAQ SDK `DAQ_PktHdr_t` fields — NEVER landed (row 20 re-cites the real
/// daq3 SDK, NEXT.md :837-:840 seam ledger; the frozen graft faces carry
/// ZERO of the two fields, the harness E4 wall measures it EVERY build). The
/// field widths ride the harness's COPY-LOCAL extension DECL face (uint16_t/
/// uint32_t) — SYNTHETIC carrier, NEVER ABI truth; the T7 ceiling vector
/// (65535 / UINT32-MAX) pins the extension DECL face, NEVER the real SDK.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracePkthLite {
    pub address_space_id: u16, // cc :52 `AS=` (the extension DECL width)
    pub tenant_id: u32,        // cc :54-:55 the `if (tenant_id)` gate + `TN=`
}

/// The row-scoped packet READ face — the arms print_ntuple touches (cc
/// :32/:41-:42/:44-:48/:51-:55): DecodeData::ip_api (decode_data.h:176)
/// REUSE-citing the landed IpApiLite (detection/rtn_checks.rs:44 — is_valid
/// lands as the get_src/get_dst Option gate, ip.h :74 verbatim); proto_bits
/// (packet.h:138) with the landed PROTO_BIT consts; ptrs.sp/dp
/// (decode_data.h:170-:171); ip_proto_next (packet.h:144, getter :278); and
/// TracePkthLite for the pkth pair. The full snort::Packet OWNER NEVER lands
/// before row 20 — cite-never-carry, NEVER forked.
#[derive(Debug, Default)]
pub struct TracePacketReadFace {
    pub ip_api: IpApiLite,        // cc :32 ip_api.is_valid() gate + :41-:42 ntop
    pub proto_bits: u32,          // cc :44 TCP|UDP GATE
    pub sp: u16,                  // DecodeData sp (decode_data.h:170)
    pub dp: u16,                  // :171
    pub ip_proto_next: IpProtocol,// cc :51 unsigned(get_ip_proto_next()) (packet.h:278; PROTO_NOT_SET=255 default face rides codec ip_protocol)
    pub pkth: TracePkthLite,      // cc :52/:54-:55
}

/// h :79-:92 the set_thread_type switch face VERBATIM: case
/// STHREAD_TYPE_PACKET -> 'P'; case STHREAD_TYPE_MAIN -> 'C'; default -> 'O'
/// (the h default arm — any OTHER value lands 'O'). SThreadType REUSE-CITED
/// from main/thread.rs:19 (one-home law — the landed thread layer owns the
/// enum; char maps NEVER fork an enum face, the nearest landed map is
/// thread_config.rs:918 stringify).
pub fn trace_thread_type_char(t: SThreadType) -> char {
    match t {
        SThreadType::Packet => 'P', // h :83-:85
        SThreadType::Main => 'C',   // h :86-:88
        SThreadType::Other => 'O',  // h :89-:90 default arm
    }
}

/// TraceLoggerPlug (h :43-:110) — the trace-logger plugin base. The C side
/// is subclassed by every PT_TRACE plug; Rust rides the concrete struct +
/// the TraceLogPlugVirt trait for the pure log(). The h NSDMI cold defaults
/// :102/:106-:109 land as the ctor face (api null / flags off / 'O' / id 0 —
/// the vectors DEFMAP line pins the face).
#[derive(Debug)]
pub struct TraceLoggerPlug {
    plugin_name: String,           // h :105 (ctor param :46 std::string)
    timestamp: bool,               // h :106 `bool timestamp = false`
    ntuple: bool,                  // h :107 `bool ntuple = false`
    thread_type: char,             // h :108 `char thread_type = 'O'`
    instance_id: u32,              // h :109 `unsigned instance_id = 0` — the harness pins a u32 face
    api: Option<&'static TraceLogApiRecord>, // h :102 `const TraceLogApi* api = nullptr` — non-owning
}

impl TraceLoggerPlug {
    /// h :46 `TraceLoggerPlug(const std::string& name) : plugin_name(name)`
    pub fn new(name: &str) -> Self {
        TraceLoggerPlug {
            plugin_name: name.to_string(),
            timestamp: false,      // h :106
            ntuple: false,         // h :107
            thread_type: 'O',      // h :108
            instance_id: 0,        // h :109
            api: None,             // h :102
        }
    }

    /// h :51-:52 `const std::string& get_name() const { return plugin_name; }`
    pub fn get_name(&self) -> &str {
        &self.plugin_name
    }

    /// h :54-:55 `void set_api(const TraceLogApi* p) { api = p; }`
    pub fn set_api(&mut self, p: &'static TraceLogApiRecord) {
        self.api = Some(p);
    }

    /// h :57-:58 `const TraceLogApi* get_api() const { return api; }`
    pub fn get_api(&self) -> Option<&'static TraceLogApiRecord> {
        self.api
    }

    /// h :60-:61 `void set_ntuple(bool flag) { ntuple = flag; }`
    pub fn set_ntuple(&mut self, flag: bool) {
        self.ntuple = flag;
    }

    /// h :63-:64 `void set_timestamp(bool flag) { timestamp = flag; }`
    pub fn set_timestamp(&mut self, flag: bool) {
        self.timestamp = flag;
    }

    /// h :66-:68 `bool get_ntuple() const` (the cppcheck suppressed face :66)
    pub fn get_ntuple(&self) -> bool {
        self.ntuple
    }

    /// h :70-:71 `bool get_timestamp() const`
    pub fn get_timestamp(&self) -> bool {
        self.timestamp
    }

    /// h :73-:74 `char get_thread_type() const` — the char face (h stores the
    /// MAPPED char, not the enum: the h :108 field is a char).
    pub fn get_thread_type(&self) -> char {
        self.thread_type
    }

    /// h :79-:92 `void set_thread_type(char t)` C arms on the enum values;
    /// the Rust seam rides SThreadType (one-home) through the h switch map.
    pub fn set_thread_type(&mut self, t: SThreadType) {
        self.thread_type = trace_thread_type_char(t); // h :81 switch face
    }

    /// h :76-:77 `unsigned get_instance_id() const`
    pub fn get_instance_id(&self) -> u32 {
        self.instance_id
    }

    /// h :94-:95 `void set_instance_id(unsigned id)`
    pub fn set_instance_id(&mut self, id: u32) {
        self.instance_id = id;
    }

    /// tracer.cc:30-:61 `std::string TraceLoggerPlug::print_ntuple(const
    /// Packet* p)` — LITERAL walk with the cc line cites.
    pub fn print_ntuple(&self, p: Option<&TracePacketReadFace>) -> String {
        // cc :32-:33 `if ( !ntuple or !p or !p->ptrs.ip_api.is_valid() )
        // return "";` — is_valid (ip.h:74 `type != IAT_NONE`) lands as the
        // IpApiLite get_src Option gate (landed face, rtn_checks.rs:60).
        if !self.ntuple {
            return String::new();
        }
        let Some(p) = p else {
            return String::new();
        };
        let (Some(src), Some(dst)) = (p.ip_api.get_src(), p.ip_api.get_dst()) else {
            return String::new();
        };

        // cc :37-:38 `uint16_t src_port = 0; uint16_t dst_port = 0;`
        let mut src_port: u16 = 0;
        let mut dst_port: u16 = 0;

        // cc :41-:42 `p->ptrs.ip_api.get_src()->ntop(src_addr);` (the SAME
        // valid arms the :32 gate just proved — the get_src nullptr face is
        // ip.h :92 IAT_NONE-guarded, unreachable here). ntop REUSE-CITES the
        // ONE landed home (sf_ip.rs:746, the test_features=false glibc face;
        // this row fixed its mid/end zero-run arm to byte-match inet_ntop —
        // the deviation rider). C's char[46] SfIpString lands as an owned
        // String (deviation row 17z/22b, file_log.rs:233 posture).
        let src_addr = src.ntop(false).expect("cc:41 valid-family face, proven by the cc:32 gate");
        let dst_addr = dst.ntop(false).expect("cc:42 valid-family face, proven by the cc:32 gate");

        // cc :44-:48 `if ( p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP)
        // ) { src_port = p->ptrs.sp; dst_port = p->ptrs.dp; }` — ICMP-only
        // packets (vectors T3) keep the 0-init ports even when the packet
        // carries dirty sp/dp (the gate face, NOT a copy).
        if p.proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP) != 0 {
            src_port = p.sp;
            dst_port = p.dp;
        }

        // cc :50 `ss << src_addr << " " << src_port << " -> " << dst_addr
        // << " " << dst_port << " ";` — the stream byte face incl the TRAILING
        // SPACE (the vectors brackets pin it: `... 80 6 AS=... ` never a lost
        // delimiter).
        let mut ss = format!("{src_addr} {src_port} -> {dst_addr} {dst_port} ");
        // cc :51 `ss << unsigned(p->get_ip_proto_next());` — the u8->unsigned
        // print face (packet.h:278 getter).
        ss.push_str(&format!("{}", u16::from(p.ip_proto_next)));
        // cc :52 `ss << " AS=" << p->pkth->address_space_id;` — ALWAYS emits
        // (vectors T4 `AS=0`; the harness-extension width face).
        ss.push_str(&format!(" AS={}", p.pkth.address_space_id));
        // cc :54-:55 `if (p->pkth->tenant_id) ss << " TN=" <<
        // p->pkth->tenant_id;` — ZERO suppresses the whole ` TN=` token.
        if p.pkth.tenant_id != 0 {
            ss.push_str(&format!(" TN={}", p.pkth.tenant_id));
        }
        // cc :57-:58 `// Delimits ... \n ss << " ";` the closing delimiter.
        ss.push(' ');
        ss
    }

    /// tracer.cc:63-:72 `std::string TraceLoggerPlug::print_timestamp()` —
    /// the C arm: `if ( !timestamp ) return "";` then `char ts
    /// [TIMEBUF_SIZE]; ts_print(nullptr, ts); return std::string(ts) + ":";`.
    /// The nullptr arm pulls the WALL CLOCK inside util.cc:146-:152 + reads
    /// SnortConfig::get_conf() util.cc:154 — the landed Rust home takes
    /// (TimeCfg, tv_sec, tv_usec) explicitly (deviation row 17i/22b; the
    /// file_log.rs:403 same-arm REUSE face); the C nullptr seam lands as the
    /// explicit time args (the harness anchor face 1710406800/123), NEVER an
    /// invented now(). The default yyyymmdd=false arm (util.h:122) is
    /// ts_print_mmdd (utils/util.rs:129 — file_log.rs:403 precedent).
    pub fn print_timestamp(&self, cfg: &TimeCfg, tv_sec: i64, tv_usec: u32) -> String {
        // cc :65-:66 `if ( !timestamp ) return "";`
        if !self.timestamp {
            return String::new();
        }
        // cc :68-:69 `char ts[TIMEBUF_SIZE]; ts_print(nullptr, ts);`
        let ts = ts_print_mmdd(cfg, tv_sec, tv_usec);
        debug_assert!(ts.len() < crate::utils::util::TIMEBUF_SIZE); // util.h:67 the 27 pin (file_log.rs:417 posture)
        // cc :71 `return std::string(ts) + ":";`
        ts + ":"
    }
}
