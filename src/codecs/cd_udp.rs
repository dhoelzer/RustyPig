//! Port of `src/codecs/ip/cd_udp.cc` (660 L) — row 18i, the head of the
//! `tools/daq3_harness` ZERO-gate probe-only DAQ trio (udp 660 / icmp4
//! 645 / icmp6 518 = 1,823 L). Ground: snort3-src @ fe29cbe, md5
//! `3c60f0f788de2da7c1d196b694d969a5`, wc 660 (both re-measured THIS
//! pass: `md5sum` + `wc -l` on the ground TU). DIR FACT: `codecs/ip/`
//! (includes face cc:25 `<daq.h>` + cc:27-:36; udp.h is one of the
//! EXACTLY 4 fresh cps of the daq3 PLAN §2, teredo.h/policy riders
//! RESIDENT).
//!
//! TRUE NAME holds this TU: file base == table name `cd_udp[]` at
//! cc:655 (REAL BUILDING_SO arms :652-:656), api struct `udp_api`
//! cc:630 (lands UDP_API — the cd_auth.rs AH_API = C-struct-name rule);
//! extern "cd_udp" resident codec_api.rs:128, the ladder NEVER
//! re-touched. vectors_faceA:5 `API udp type=0 size=112 ver=1900547
//! name=udp` + :6 HELP + :7 `udp mod_ctor=1 mod_dtor=1` (mod pair TRUE
//! uniform).
//!
//! THE DAQ SEAM — THE graft ruling (daq3 PLAN §2a, this row's head-on
//! face): the DAQ SDK header is ABSENT ground-side (find whole-repo = 0
//! at fe29cbe); the harness GRAFT `tools/daq3_harness/copy/daq.h` (md5
//! `73fdbc3983ca45246b554c46efdf1ad1`, re-run THIS pass) is SYNTHETIC:
//! shapes drawn ONLY from the measured call faces cc:263-:270 +
//! :420-:424; the bitfield order/width is NEVER ABI truth (PLAN §9 R1;
//! the 17d left-open seam — the copy-tree framework/codec.h :38
//! `struct _daq_msg;` fwd decl is ALL the tree carries; raw.daq_msg
//! provenance stays OPEN, real DAQ = plan row 20). The Rust face
//! mirrors the C read shape EXACTLY as row-scoped types (DaqPdd/
//! DaqNapt below): `valid_checksum_from_daq` lands VERBATIM statement-
//! for-statement (cc:261-:276), the `Option<DaqPdd>` modelling
//! `daq_msg_get_meta` nullptr (the witness arms it via probe_daq_enable
//! — witness_daq.cc:29), and the cc:271 pointer difference
//! `raw.data - daq_msg_get_data(raw.daq_msg)` rides as an explicit
//! `i64` param (the probe witness pins that quantity against its
//! static fake_payload, witness_daq.cc:23 — pointer math probe-faked,
//! NEVER ABI). `stats.cksum_bypassed++` (cc:274) is the PEG cite-
//! never-land face (R2; small4 cd_pgm tri-state precedent; counters
//! NEVER printed by any vector).
//!
//! THE DUAL-FACE HEADLINE (vectors:9/:10/:11; probe_dec.cc:58-:83):
//! the SAME bad-checksum packet (uh_chk 0xFFFF, uh_len == raw.len)
//! reads `UDP cksumbad-daqoff -> 0 dflags=4 gate=1` (vectors:9 — DAQ
//! meta OFF -> the real checksum path writes DECODE_ERR_CKSUM_UDP,
//! decode_data.h:133 = 4; the gate face udp_checksums()==1 printed
//! LIVE) vs `UDP cksumbad-daqvalid -> 1 dflags=0 next=17` (vectors:10
//! — synthetic DAQ-valid pdd -> valid_checksum_from_daq TRUE -> the
//! whole cc:367-:415 checksum arm SKIPPED, checksum_bypassed PEG rides
//! cite-never-land) and `UDP daqoffsetmismatch -> 0 dflags=4`
//! (vectors:11 — l4_offset 0 != the payload offset, the cc:268-:272
//! fallback arm, SAME flag face as daq-OFF). The gate rides the LANDED
//! `crate::main::policy::NetworkPolicy` (witness pins the ground NSDMI
//! face policy.h:233 checksum_eval = ALL|DEF so udp_checksums() == 1 —
//! witness_daq.cc:43-:50; the inline face policy.h:205-:206; the three
//! ground gate sites cc:367 / cd_icmp4.cc:159 / cd_icmp6.cc:197; the
//! `peg-vs-hook` correction stands: nm census 0 tunnel_bypass x3 —
//! this row NEVER touches codec.tunnel_bypass).
//!
//! THE PARAMS SEAM (R4 honest record): `Value::get_bits(PortBitSet&)`
//! lands EMPTY-RESET in the harness witness (witness_daq.cc:51) and is
//! NEVER armored through a DEC vector — the module set() PT_BIT_LIST
//! arms land as the name-match read-back face (cd_esp.rs EspModule::
//! set cc:58-:66 precedent) fed by the caller's bitset, and the config
//! DEFAULT ports (GTP_U_PORT 2152 etc, cc:91-:94) land as consts. The
//! landed Parameter has NO range slot (parameter.rs:36-:41): the
//! PT_BIT_LIST `"65535"` RANGE (cc:67/:70/:73 middle args) is a
//! DOC-CITE only, never a Rust field.
//!
//! PEGS cite-never-land (cc:45-:60 PegInfo/Stats/THREAD_LOCAL + the
//! get_pegs/get_counts overrides cc:182-:187): the three rows ride
//! THIS comment — CountType::SUM `bad_udp4_checksum` "nonzero udp over
//! ipv4 checksums" (cc:47) / SUM `bad_udp6_checksum` "nonzero udp over
//! ipv6 checksums" (cc:48) / SUM `checksum_bypassed` "checksum
//! calculations bypassed" (cc:49); the cc:384/:403 counter SELECTS and
//! the cc:410 increment are the cc bad_cksum_cnt PEG latch, NO Rust
//! machinery (the cd_gtp/cd_geneve comment-pin precedent).
//!
//! GATE-ORDER FACT (vectors:19 `UDP teredo3544 -> 1 next=257`): the C
//! if-chain order is gtp FIRST (cc:443) else-if teredo (cc:449) else-if
//! vxlan (cc:455) else-if geneve (cc:460) — NEVER reorder. With the
//! config DEFAULTS (gtp_decode true + ports {2152, 3386}, cc:101-:102)
//! a dst-3544 packet (probe BE 0x0DD8, probe_dec.cc:102) hits NO gtp
//! port and answers TEREDO (protocol_ids.h:128 0x0101 = 257);
//! PROTO_BIT__UDP_TUNNELED (decode_data.h:106 0x080000) rides at
//! cc:466-:467 because next != FINISHED_DECODE. NAPT face: vectors:14
//! `UDP napt-hit -> 1 sp=3000 dp=6000` (BE napt ports ntohs'd cc:423-
//! :424; probe pins ports htons(3000)/htons(6000) + ip_layer 0 ==
//! codec.ip_layer_cnt, cc:421, probe_dec.cc:72) vs vectors:15/:16
//! `EV 116 447` + `UDP naptmiss-portzero -> 1 sp=0 dp=0` (EV 447 from
//! UDPMiscTests cc:480-:481); large4020 vectors:17/:18 = pay_len 4012
//! \> 4000 -> EV 445 cc:477-:478. sids ALL resident codec_module.rs:
//! 84-:87 (95/96/97/98 = h:64-:67), :165 (406 = h:160), :203 (445 =
//! h:198), :205 (447 = h:200) — ZERO new constants; vectors:21
//! `UDPRULES 7 sid0=95 name=udp`. UDP is the trio's CONFIG codec: the
//! 3-arg BaseCodecModule ctor (cc:162) contrasts the icmp4/icmp6
//! plain-2-arg siblings (no udp-like params table there).

use crate::codecs::checksum::{Pseudoheader, Pseudoheader6, udp_cksum4, udp_cksum6};
use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CODEC_UNSURE_ENCAP, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord,
    CodecData, CodecTable, EncState, EncodeFlags, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink,
    RawData, UPD_COOKED, UPD_REBUILT_FRAG, ip_protocol, protocol_id,
};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::main::policy::NetworkPolicy;
use crate::ports::port_utils::PortBitSet;

/// cc:40 `#define CD_UDP_NAME "udp"`
pub const CD_UDP_NAME: &str = "udp";
/// cc:41 `#define CD_UDP_HELP "support for user datagram protocol"` —
/// vectors_faceA:6 HELP face.
pub const CD_UDP_HELP: &str = "support for user datagram protocol";

/// udp.h:29 `constexpr uint8_t UDP_HEADER_LEN = 8` — the length-ladder
/// subject (cc:318/:349), the encode allocate (cc:503) and the log Len
/// adjust (cc:491).
pub const UDP_HEADER_LEN: u8 = 8;

/// cc:91-:94 the four default-port consts (the config ctor sets exactly
/// these, cc:101-:104; the same numbers ride the udp_params DEFAULT
/// strings "2152 3386" cc:68 / "4789" cc:71 / "6081" cc:74).
pub const GTP_U_PORT: u16 = 2152;
pub const GTP_U_PORT_V0: u16 = 3386; // cc:92 `constexpr uint16_t GTP_U_PORT_V0 = 3386`
pub const VXLAN_U_PORT: u16 = 4789;
pub const GENEVE_U_PORT: u16 = 6081;

/// teredo.h:29 `TEREDO_PORT = 3544` (row-scoped home; the cd_teredo.rs
/// `:58` twin lives in ITS module scope — a different module, no clash,
/// same cite posture).
pub const TEREDO_PORT: u16 = 3544;
/// teredo.h:38-:39 `is_teredo_port(uint16_t port) { return port ==
/// TEREDO_PORT; }` — the cc:449-:450 double read (src_port then
/// dst_port).
#[inline]
pub fn is_teredo_port(port: u16) -> bool {
    port == TEREDO_PORT
}

/// protocol_ids.h:128 `TEREDO = 0x0101` (== 257; vectors:19 next=257)
/// — row-scoped home, the cd_teredo.rs PROTOCOL_ID_TEREDO (:96)
/// precedent; framework/codec.rs byte-UNTOUCHED (18g/18h posture).
pub const PROTOCOL_ID_TEREDO: ProtocolId = 0x0101;
/// protocol_ids.h:129 `GTP = 0x0102` — the cc:447 arm target (cd_gtp.rs
/// PROTOCOL_ID_GTP rides ITS module at the same value; different module
/// scope, both cited to protocol_ids.h:129, no collision).
pub const PROTOCOL_ID_GTP: ProtocolId = 0x0102;
/// protocol_ids.h:135 `VXLAN = 0x0108` — the cc:458 arm target.
pub const PROTOCOL_ID_VXLAN: ProtocolId = 0x0108;
/// protocol_ids.h:136 `GENEVE = 0x0109` — the cc:463 arm target.
pub const PROTOCOL_ID_GENEVE: ProtocolId = 0x0109;

/// decode_data.h:89 `#define PROTO_BIT__UDP 0x000004` — the cc:437 OR
/// (vectors:10 `next=17` arm rides it; bits never printed — the
/// vectors face prints ret/dflags/next only, the write is by
/// construction from the cite).
pub const PROTO_BIT__UDP: u32 = 0x000004;
/// decode_data.h:106 `#define PROTO_BIT__UDP_TUNNELED 0x080000` — the
/// cc:467 conditional OR (rides vectors:19, next=257).
pub const PROTO_BIT__UDP_TUNNELED: u32 = 0x080000;
/// decode_data.h:133 `DECODE_ERR_CKSUM_UDP = 0x00000004` — the vectors
/// `dflags=4` writes (cc:411; the :9/:11 dual-face arms).
pub const DECODE_ERR_CKSUM_UDP: u64 = 0x00000004;
/// decode_data.h:141 `DECODE_FRAG = 0x00000040` (row-scoped home; the
/// cd_frag.rs:80 twin rides its own module) — the cc:329 length-ladder
/// fork READ and the cc:446 gtp inner-guard READ. NEVER vector-armed
/// (no DEC arm sets DECODE_FRAG — probe_dec never touches gd
/// .decode_flags before udp decode) but ported LITERAL, never dropped:
/// the fragmented-udp faces stay unit face only.
pub const DECODE_FRAG: u64 = 0x00000040;

// ---- udp.h:31-:62 `struct UDPHdr` overlay face (ports @0 LE-wire-
// BE-read pair, len @4-5, chk @6-7; udp.h:33-:36 uint16 members): the
// formatted accessors udp.h:39-:49 (`src_port()/dst_port()/len()/
// cksum()`, each `ntohs` = the BE read on the pinned LE host, the
// gre_proto posture) and the raw slots udp.h:52-:62. The decode arms
// use the formatted pair (cc:428-:429), the uh_chk TRUTHINESS arms
// cc:379/:389 read the raw slot != 0, the log reads the BE trio
// (cc:490-:491), encode/format swap raw slots. get-or-0 posture: the
// guards upstream prove the 8-byte window (cc:318); short hostile
// inputs stay panic-free where C over-reads (the cd_hop_opts
// posture, never armed in replay). ----

/// udp.h:39-:41 `src_port() { return ntohs(uh_sport); }` — bytes 0-1.
#[inline]
pub fn udp_src_port(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([*pkt.first().unwrap_or(&0), *pkt.get(1).unwrap_or(&0)])
}
/// udp.h:42-:43 `dst_port() { return ntohs(uh_dport); }` — bytes 2-3.
#[inline]
pub fn udp_dst_port(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([*pkt.get(2).unwrap_or(&0), *pkt.get(3).unwrap_or(&0)])
}
/// udp.h:45-:46 `len() { return ntohs(uh_len); }` — bytes 4-5.
#[inline]
pub fn udp_len(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([*pkt.get(4).unwrap_or(&0), *pkt.get(5).unwrap_or(&0)])
}
/// udp.h:58-:59 `raw_len() { return uh_len; }` — the RAW slot value as
/// stored (LE-host read of the BE bytes 4-5; the cc:534 pseudoheader
/// alias read `ps.hdr.len = udph_out->uh_len` rides this face).
#[inline]
pub fn udp_raw_len_slot(pkt: &[u8]) -> u16 {
    u16::from_le_bytes([*pkt.get(4).unwrap_or(&0), *pkt.get(5).unwrap_or(&0)])
}
/// udp.h:61-:62 `raw_cksum() { return uh_chk; }` — the slot used at
/// the cc:379/:389 truthiness arms (`!= 0` — the BE-vs-LE read is
/// value-irrelevant for the zero test; the BE face kept on the slice).
#[inline]
pub fn udp_raw_chk(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([*pkt.get(6).unwrap_or(&0), *pkt.get(7).unwrap_or(&0)])
}

/// cc:62-:77 `static const Parameter udp_params[]` — the FOUR config
/// rows + the PT_MAX terminator (5 slots; this is udp's contrast arm:
/// the ONLY codec of the trio WITH a params table — grep ground:
/// udp_params cc:62 only; icmp4/icmp6 modules are 2-arg). The
/// PT_BIT_LIST range `"65535"` (cc:67/:70/:73) has NO slot in the
/// landed Parameter (parameter.rs:36-:41) — DOC-CITE only (module doc
/// PARAMS SEAM).
pub const UDP_PARAMS: [Parameter; 5] = [
    Parameter {
        name: Some("deep_teredo_inspection"), // cc:64
        ptype: PtType::PtBool,                // cc:64 Parameter::PT_BOOL
        deflt: Some("false"),                 // cc:64 (help: cc:65)
    },
    Parameter {
        name: Some("gtp_ports"),   // cc:67
        ptype: PtType::PtBitList,  // cc:67 (range "65535" doc-cited)
        deflt: Some("2152 3386"),  // cc:68
    },
    Parameter {
        name: Some("vxlan_ports"), // cc:70
        ptype: PtType::PtBitList,  // cc:70
        deflt: Some("4789"),       // cc:71
    },
    Parameter {
        name: Some("geneve_ports"), // cc:73
        ptype: PtType::PtBitList,   // cc:73
        deflt: Some("6081"),        // cc:74
    },
    Parameter {
        name: None,           // cc:76 terminator
        ptype: PtType::PtMax, // cc:76 Parameter::PT_MAX
        deflt: None,
    },
];

/// cc:79-:89 `static const RuleMap udp_rules[]` — SEVEN rows + the
/// `{ 0, nullptr }` terminator; sids ALL resident (CodecSid walk:
/// 95/96/97/98 codec_module.rs:84-:87, 406 :165, 445 :203, 447 :205 —
/// h:64-:67/:160/:198/:200), msg strings verbatim. vectors:21
/// `UDPRULES 7 sid0=95 name=udp` (the `while (rm[n].sid) n++` probe
/// walk, probe_dec.cc:106).
pub const UDP_RULES: [RuleMap; 8] = [
    RuleMap {
        sid: CodecSid::DECODE_UDP_DGRAM_LT_UDPHDR as u32, // 95
        msg: Some("truncated UDP header"), // cc:81 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_UDP_DGRAM_INVALID_LENGTH as u32, // 96
        msg: Some("invalid UDP header, length field < 8"), // cc:82 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_UDP_DGRAM_SHORT_PACKET as u32, // 97
        msg: Some("short UDP packet, length field > payload length"), // cc:83 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_UDP_DGRAM_LONG_PACKET as u32, // 98
        msg: Some("long UDP packet, length field < payload length"), // cc:84 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_UDP_IPV6_ZERO_CHECKSUM as u32, // 406
        msg: Some("invalid IPv6 UDP packet, checksum zero"), // cc:85 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_UDP_LARGE_PACKET as u32, // 445
        msg: Some("large UDP packet (> 4000 bytes)"), // cc:86 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_UDP_PORT_ZERO as u32, // 447
        msg: Some("UDP port 0 traffic"), // cc:87 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:88 terminator
];

/// cc:96-:157 `class UdpCodecConfig` — the ctor cc:99-:105 sets
/// gtp_ports {GTP_U_PORT, GTP_U_PORT_V0}, vxlan/geneve their one
/// default port; the private NSDMIs cc:150-:156: enable_teredo = false
/// (:150), gtp/vxlan/geneve_decode all TRUE (:154-:156). The
/// PortBitSet rides the LANDED ports/port_utils face (C
/// std::bitset<MAX_PORTS> twin). Predicate fns copy the inline faces
/// cc:107-:129 one-for-one; the set_*_ports pair cc:131-:147 assigns
/// the bits AND re-derives the decode latch from `ports.any()`
/// (count() > 0 face). The set_* trio is reached ONLY through the
/// module set() PARAMS SEAM (R4 — the witness get_bits is the empty
/// reset, witness_daq.cc:51; NEVER armored through a DEC vector).
#[derive(Debug)]
pub struct UdpCodecConfig {
    enable_teredo: bool, // cc:150
    gtp_ports: PortBitSet,
    vxlan_ports: PortBitSet,
    geneve_ports: PortBitSet,
    gtp_decode: bool,    // cc:154 default true
    vxlan_decode: bool,  // cc:155 default true
    geneve_decode: bool, // cc:156 default true
}

impl UdpCodecConfig {
    /// cc:99-:105 the ctor face: exactly the four default-port sets.
    pub fn new() -> UdpCodecConfig {
        let mut c = UdpCodecConfig {
            enable_teredo: false,   // cc:150
            gtp_ports: PortBitSet::new(),
            vxlan_ports: PortBitSet::new(),
            geneve_ports: PortBitSet::new(),
            gtp_decode: true,   // cc:154
            vxlan_decode: true, // cc:155
            geneve_decode: true, // cc:156
        };
        c.gtp_ports.set_bit(usize::from(GTP_U_PORT));      // cc:101
        c.gtp_ports.set_bit(usize::from(GTP_U_PORT_V0));   // cc:102
        c.vxlan_ports.set_bit(usize::from(VXLAN_U_PORT));  // cc:103
        c.geneve_ports.set_bit(usize::from(GENEVE_U_PORT)); // cc:104
        c
    }

    /// cc:107-:108 `deep_teredo_inspection()`
    pub fn deep_teredo_inspection(&self) -> bool {
        self.enable_teredo
    }
    /// cc:110-:111 `set_teredo_inspection(bool val)`
    pub fn set_teredo_inspection(&mut self, val: bool) {
        self.enable_teredo = val;
    }
    /// cc:113-:114 `gtp_decoding()`
    pub fn gtp_decoding(&self) -> bool {
        self.gtp_decode
    }
    /// cc:116-:117 `is_gtp_port` — `gtp_ports.test(port)`.
    pub fn is_gtp_port(&self, port: u16) -> bool {
        self.gtp_ports.test(usize::from(port))
    }
    /// cc:119-:120 `vxlan_decoding()`
    pub fn vxlan_decoding(&self) -> bool {
        self.vxlan_decode
    }
    /// cc:122-:123 `geneve_decoding()`
    pub fn geneve_decoding(&self) -> bool {
        self.geneve_decode
    }
    /// cc:125-:126 `is_vxlan_port`
    pub fn is_vxlan_port(&self, port: u16) -> bool {
        self.vxlan_ports.test(usize::from(port))
    }
    /// cc:128-:129 `is_geneve_port`
    pub fn is_geneve_port(&self, port: u16) -> bool {
        self.geneve_ports.test(usize::from(port))
    }
    /// cc:131-:135 `set_gtp_ports` — assign + latch from any():
    pub fn set_gtp_ports(&mut self, ports: &PortBitSet) {
        self.gtp_ports = ports.clone();       // cc:133
        self.gtp_decode = ports.count() > 0;  // cc:134 `ports.any()`
    }
    /// cc:137-:141 `set_vxlan_ports`
    pub fn set_vxlan_ports(&mut self, ports: &PortBitSet) {
        self.vxlan_ports = ports.clone();      // cc:139
        self.vxlan_decode = ports.count() > 0; // cc:140
    }
    /// cc:143-:147 `set_geneve_ports`
    pub fn set_geneve_ports(&mut self, ports: &PortBitSet) {
        self.geneve_ports = ports.clone();      // cc:145
        self.geneve_decode = ports.count() > 0; // cc:146
    }
}

impl Default for UdpCodecConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:159-:197 `class UdpModule : public BaseCodecModule` — the THREE-
/// arg ctor cc:162 carries udp_params (the trio's config codec, module
/// doc). The dtor cc:167-:174 (`if (config) delete ...; config =
/// nullptr`) folds onto the Rust Option drop (18d stack-owned
/// posture). get_rules cc:179-:180. get_pegs/get_counts cc:182-:187 =
/// the PEG cite-never-land overrides (module doc pegs block).
#[derive(Debug)]
pub struct UdpModule {
    pub base: BaseCodecModule,
    config: Option<UdpCodecConfig>, // cc:196 `UdpCodecConfig* config`
}

impl UdpModule {
    /// cc:162-:165 `UdpModule() : BaseCodecModule(CD_UDP_NAME,
    /// CD_UDP_HELP, udp_params) { config = nullptr; }`
    pub fn new() -> UdpModule {
        UdpModule {
            base: BaseCodecModule::new_with_params(CD_UDP_NAME, CD_UDP_HELP, &UDP_PARAMS),
            config: None, // cc:164
        }
    }

    /// cc:179-:180 `get_rules()` override -> udp_rules. vectors:21
    /// `UDPRULES 7`.
    pub fn get_rules() -> &'static [RuleMap] {
        &UDP_RULES
    }

    /// vectors:21 `name=udp` (Module::get_name over the cc:162 slot).
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }

    /// cc:199-:224 `UdpModule::set(const char*, Value& v, SnortConfig*)`
    /// — the name-match read-back face (the EspModule::set cc:58-:66
    /// precedent; UDP's four-arm variant). The deep_teredo arm lands
    /// the bool verbatim (cc:203-:205 `v.is(...) -> set_teredo_
    /// inspection(v.get_bool())`); the THREE PT_BIT_LIST arms
    /// (cc:207-:221) carry the PARAMS SEAM (R4): `v.get_bits(ports)`
    /// is modelled by the `ports` param, and the harness witness arms
    /// that symbol ONLY with the empty reset (witness_daq.cc:51
    /// `b.reset()`) — the config latch then lands FALSE via the cc:134
    /// any() re-derive, exactly the witness face; NEVER armored through
    /// a DEC vector (staged-LINK census arms it, daq3 PLAN §0). The C
    /// `PortBitSet ports;` local cc:201 is the fresh default — the
    /// caller hands the same fresh bitset. cc:223 `return true` is
    /// UNCONDITIONAL — NO esp-style else-false arm (literal).
    pub fn set(&mut self, name: &str, bool_value: bool, ports: &PortBitSet) -> bool {
        if name == "deep_teredo_inspection" {
            if let Some(c) = self.config.as_mut() {
                c.set_teredo_inspection(bool_value); // cc:205
            }
        } else if name == "gtp_ports" {
            if let Some(c) = self.config.as_mut() {
                c.set_gtp_ports(ports); // cc:209-:210
            }
        } else if name == "vxlan_ports"
            && let Some(c) = self.config.as_mut()
        {
            c.set_vxlan_ports(ports); // cc:214-:215
        } else if name == "geneve_ports"
            && let Some(c) = self.config.as_mut()
        {
            c.set_geneve_ports(ports); // cc:219-:220
        }
        true // cc:223
    }

    /// cc:226-:231 `UdpModule::begin(const char*, int, SnortConfig*)`
    /// — `assert(!config)` is the debug-only C face (no Rust twin, the
    /// 18g asserts-stay-out ruling) then the new-config face cc:229.
    pub fn begin(&mut self) -> bool {
        self.config = Some(UdpCodecConfig::new()); // cc:229
        true // cc:230
    }

    /// cc:188-:193 `get_data()` — THE steal face: `tmp = config;
    /// config = nullptr; return tmp;` -> Option::take.
    pub fn get_data(&mut self) -> Option<UdpCodecConfig> {
        self.config.take() // cc:190-:192
    }
}

impl Default for UdpModule {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// THE DAQ seam (row 18i) — ruled in the module doc. The graft
// copy/daq.h (md5 73fdbc39, SYNTHETIC; 17d left-open; `struct
// _daq_msg;` fwd = copy-tree framework/codec.h :38 face) shapes below
// are drawn ONLY from the measured call faces — NEVER ABI truth
// (PLAN §9 R1; reuse bank: 7 TUs include <daq.h> ground-side, the
// later heavyweight rows ride the SAME face at row 20).
// ============================================================================

/// graft daq.h:15 `#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)` — the
/// cc:268 compare (C int32 slot; compared pdd.l4_offset != -1).
pub const DAQ_PKT_DECODE_OFFSET_INVALID: i64 = -1;

/// graft daq.h:16-:22 `DAQ_PktDecodeData_t` — the flags.bits bitfield
/// group {l4_checksum, udp, icmp, l4} (graft `unsigned x : 1` face,
/// order SYNTHETIC, NEVER ABI) + `int32_t l4_offset`. Read face
/// cc:265-:268 (three udp-guard bits; icmp rides the icmp twins' arms).
#[derive(Copy, Clone, Default)]
pub struct DaqPdd {
    pub l4_checksum: bool,
    pub udp: bool,
    pub icmp: bool,
    pub l4: bool,
    pub l4_offset: i64, // the grafted int32_t slot
}

/// graft daq.h:23-:27 `DAQ_NAPTInfo_t` — src_port/dst_port (`uint32_t`
/// slots on the graft, wire-BE values: the face cc:423-:424 `ntohs`) +
/// ip_layer (compared against codec.ip_layer_cnt at cc:421).
#[derive(Copy, Clone, Default)]
pub struct DaqNapt {
    pub src_port_be: u16,
    pub dst_port_be: u16,
    pub ip_layer: u8,
}

/// The decode-call DAQ parameter bundle (the cd_icmp4.rs/cd_icmp6.rs
/// trio shape: pdd + the cc:271 pointer-difference ride as one Copy
/// parameter, keeping decode at 7 args inside the clippy arg-count gate
/// with NO allowance — the trio-consistency rule; the udp bundle ADDS
/// the cc:420 NAPT_INFO meta arm the icmp twins never read).
#[derive(Copy, Clone, Default)]
pub struct DaqFace {
    pub pdd: Option<DaqPdd>,    // cc:264 DECODE_DATA meta face
    pub napt: Option<DaqNapt>,  // cc:420 NAPT_INFO meta face
    pub payload_delta: i64,     // cc:271 pointer-difference face
}

/// The row-scoped DecodeData seam (the 18e IpApiLite precedent; NOT a
/// DecodeData port): the cc:329/:446 decode_flags READS (fresh face =
/// 0, the probe fixture posture probe_dec.cc:47 `DecodeData d`), the
/// cc:411 DECODE_ERR_CKSUM_UDP WRITE (vectors dflags=4 face), the
/// cc:434-:435 sp/dp WRITES read back by UDPMiscTests cc:480-:481 and
/// printed vectors:14/:16, and the ip_api READ faces: is_ip6()
/// (cc:333), is_ip4() (cc:373), the get_ip4h() wire-header window
/// (cc:343 — len() = ntohs bytes 2-3 ipv4.h:68-:69; hlen() =
/// (byte0 & 0x0f) << 2 ipv4.h:59-:60; sip/dip = get_src()/get_dst()
/// = the raw uint32 slots at bytes 12-15/16-19, ipv4.h:55-:56 +
/// :127-:130) and get_ip6h() (cc:335 — len() = ntohs(ip6_payload_len)
/// bytes 4-5, ipv6.h:71-:72; get_src()/get_dst() u6_addr32/8 faces,
/// ipv6.h:56 + :97-:101). cc:338's pointer difference
/// `(udph - snort.ip_api.ip_data())` lands as the explicit
/// `ip_data_udp_off` count face (the left-open pointer face folded to
/// its observable quantity; NEVER armed — DECODE_FRAG never set in
/// the probe). cc:433 `snort.udph = udph` is the overlay-alias write:
/// the Rust pins the overlay on raw.data — no field twin (document
/// pin). set_pkt_type(PktType::UDP) (cc:438/:605; enum class face
/// decode_data.h:45-:48 `NONE, IP, TCP, UDP, ...`) has NO landed Rust
/// home — document-pinned, never modeled.
#[derive(Copy, Clone, Default)]
pub struct UdpDecodeData {
    pub decode_flags: u64,          // cc:329/:446 read, cc:411 write
    pub sp: u16,                    // cc:434 write, cc:480 read
    pub dp: u16,                    // cc:435 write, cc:481 read
    pub is_ip4: bool,               // cc:373
    pub is_ip6: bool,               // cc:333
    pub ip4h: Option<&'static [u8]>, // cc:343 the 20-byte wire header face
    pub ip6h: Option<&'static [u8]>, // cc:335 the 40-byte wire header face
    pub ip_data_udp_off: u16, // cc:338 (udph - ip_data()) folded quantity
}

// The ip header field faces at the seam reads (row-scoped fns, the
// gre.h overlay pattern; get-or-0 posture as everywhere above).

/// ipv4.h:68-:69 `len() { return ntohs(ip_len); }` — bytes 2-3.
#[inline]
fn ip4_len(h: &[u8]) -> u16 {
    u16::from_be_bytes([*h.get(2).unwrap_or(&0), *h.get(3).unwrap_or(&0)])
}
/// ipv4.h:59-:60 `hlen() { return (uint8_t)((ip_verhl & 0x0f) << 2); }`
#[inline]
fn ip4_hlen(h: &[u8]) -> u8 {
    (*h.first().unwrap_or(&0) & 0x0f) << 2
}
/// ipv4.h:55 + :127-:128 `get_src() { return ip_src; }` — the raw
/// uint32 slot, bytes 12-15 (LE-host memcpy face, the wire-order bits
/// the C pseudoheader stores).
#[inline]
fn ip4_sip(h: &[u8]) -> u32 {
    u32::from_le_bytes([
        *h.get(12).unwrap_or(&0),
        *h.get(13).unwrap_or(&0),
        *h.get(14).unwrap_or(&0),
        *h.get(15).unwrap_or(&0),
    ])
}
/// ipv4.h:56 + :129-:130 `get_dst()` — bytes 16-19.
#[inline]
fn ip4_dip(h: &[u8]) -> u32 {
    u32::from_le_bytes([
        *h.get(16).unwrap_or(&0),
        *h.get(17).unwrap_or(&0),
        *h.get(18).unwrap_or(&0),
        *h.get(19).unwrap_or(&0),
    ])
}
/// ipv6.h:71-:72 `len() { return ntohs(ip6_payload_len); }` — bytes 4-5.
#[inline]
fn ip6_len(h: &[u8]) -> u16 {
    u16::from_be_bytes([*h.get(4).unwrap_or(&0), *h.get(5).unwrap_or(&0)])
}
/// ipv6.h:56 (`uint32_t u6_addr32[4]`) + :97-:98 get_src() — the
/// address bytes 8-23 as four u32 words as stored (the COPY4
/// cc:298-:299 word-identity face riding the checksum.rs arr view).
#[inline]
fn ip6_sip_words(h: &[u8]) -> [u32; 4] {
    ip6_addr_words(h, 8)
}
/// ipv6.h:99-:101 `get_dst()` — the address bytes 24-39.
#[inline]
fn ip6_dip_words(h: &[u8]) -> [u32; 4] {
    ip6_addr_words(h, 24)
}

/// the cc:298 COPY4 / cc:541-:542 memcpy / cc:581-:582 u6_addr32
/// faces: `off` is the address start in the ip6 wire header (8 src /
/// 24 dst); four u32 words AS STORED (LE-host memcpy identity — the
/// bytes round-trip unchanged; the memcpy-vs-word-copy pair cc:541
/// (u6_addr8) vs cc:581 (u6_addr32) lands the SAME bytes, identity
/// kept).
fn ip6_addr_words(h: &[u8], off: usize) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (i, slot) in w.iter_mut().enumerate() {
        *slot = u32::from_le_bytes([
            *h.get(off + 4 * i).unwrap_or(&0),
            *h.get(off + 4 * i + 1).unwrap_or(&0),
            *h.get(off + 4 * i + 2).unwrap_or(&0),
            *h.get(off + 4 * i + 3).unwrap_or(&0),
        ]);
    }
    w
}

/// cc:234-:258 `class UdpCodec : public Codec` — the config POINTER
/// cc:257 lands owned (Box): the dtor `~UdpCodec() { delete config; }`
/// cc:238 is the Rust drop face (18d posture). ctor cc:237 keeps
/// Codec(CD_UDP_NAME) riding the record name slot.
pub struct UdpCodec {
    config: Box<UdpCodecConfig>, // cc:257
}

impl UdpCodec {
    /// cc:237 `UdpCodec(UdpCodecConfig* c) : Codec(CD_UDP_NAME)
    /// { config = c; }`
    pub fn new(config: Box<UdpCodecConfig>) -> UdpCodec {
        UdpCodec { config }
    }

    /// cc:308-:311 out-of-line def — `v.emplace_back(ProtocolId::UDP)`;
    /// protocol_ids.h UDP = 17 (:96-:98 face, the landed
    /// protocol_id::UDP home reused). vectors:20 `UDPPID 17 n=1`.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::UDP); // cc:310
    }

    /// cc:261-:276 `valid_checksum_from_daq(const RawData&)` — the
    /// VERBATIM face (module doc rules the seam): cc:263-:266 the
    /// nullptr-or-flag-bits guard (three udp arms: l4_checksum, udp,
    /// l4 — the `icmp` bit is read by the icmp twins, carried by
    /// DaqPdd for graft fidelity); cc:267 the "Sanity check" comment;
    /// cc:268-:273 the offset arm (raw_data_minus_data = the witness-
    /// pinned pointer quantity, NEVER ABI); cc:274 the cksum_bypassed
    /// PEG bump — cite-never-land, NO Rust counter; cc:275 true.
    pub fn valid_checksum_from_daq(
        pdd: Option<DaqPdd>,
        offset_invalid: i64,
        raw_data_minus_data: i64,
    ) -> bool {
        let pdd = match pdd {
            // cc:265 `!pdd || !bits.l4_checksum || !bits.udp || !bits.l4`
            Some(p) if p.l4_checksum && p.udp && p.l4 => p,
            _ => return false, // cc:266
        };
        if pdd.l4_offset != offset_invalid {
            // cc:270-:272 the same-thing sanity compare (daq_msg_get_
            // data face folded into the param, module doc):
            if raw_data_minus_data != pdd.l4_offset {
                return false; // cc:272
            }
        }
        // cc:274 stats.cksum_bypassed++ — PEG cite-never-land (module
        // doc pegs block; vectors:10 prints only ret/dflags/next — the
        // counter never surfaces).
        true // cc:275
    }

    /// cc:278-:291 `valid_checksum4` — the pseudoheader fill VERBATIM
    /// on the landed checksum.rs field shapes: sip/dip via get_src()/
    /// get_dst() (cc:283-:284), zero = 0 (cc:285), protocol =
    /// IpProtocol::UDP (cc:286, the u8 newtype home ip_protocol::UDP =
    /// 17), len = htons((uint16_t)raw.len) (cc:287 — the network-order
    /// bit face, the checksum.rs :56-:58 `len` slot pin: the field
    /// holds the to_be VALUE on the LE host); the ==0 validation (cc:
    /// 290 — the cppcheck note "zero is the valid packet checksum
    /// result" rides).
    fn valid_checksum4(raw: &RawData, snort: &UdpDecodeData) -> bool {
        let ip4h = snort.ip4h.unwrap_or(&[]); // cc:280 get_ip4h()
        let ph = Pseudoheader {
            sip: ip4_sip(ip4h),                            // cc:283
            dip: ip4_dip(ip4h),                            // cc:284
            zero: 0,                                       // cc:285
            protocol: ip_protocol::UDP,                    // cc:286
            len: u16::to_be(raw.len as u16),               // cc:287 htons
        };
        udp_cksum4(raw.data, raw.len as usize, ph) == 0 // cc:290 (declared-len posture, checksum.rs:175-:179)
    }

    /// cc:293-:306 `valid_checksum6` — COPY4 the u6_addr32 words
    /// (cc:298-:299), zero = 0 (cc:300), protocol =
    /// codec.ip6_csum_proto (cc:301 — the CodecData read, NOT fixed
    /// UDP), len = htons (cc:302); ==0 (cc:305).
    fn valid_checksum6(raw: &RawData, codec: &CodecData, snort: &UdpDecodeData) -> bool {
        let ip6h = snort.ip6h.unwrap_or(&[]); // cc:295 get_ip6h()
        let ph6 = Pseudoheader6 {
            sip: ip6_sip_words(ip6h),                    // cc:298 COPY4
            dip: ip6_dip_words(ip6h),                    // cc:299
            zero: 0,                                     // cc:300
            protocol: codec.ip6_csum_proto,              // cc:301
            len: u16::to_be(raw.len as u16),             // cc:302
        };
        udp_cksum6(raw.data, raw.len as usize, ph6) == 0 // cc:305
    }

    /// cc:313-:470 out-of-line decode, statement order VERBATIM. The
    /// netpol param carries the cc:367 `snort::get_network_policy()`
    /// read (vectors:9 `gate=1` printed LIVE, probe_dec.cc:64); the
    /// DaqFace bundle carries the two `daq_msg_get_meta` faces (cc:264
    /// DECODE_DATA / cc:420 NAPT_INFO — Option = the witness nullptr
    /// arms, witness_daq.cc:29) + the cc:271 `raw.data -
    /// daq_msg_get_data(...)` difference (the payload_delta model);
    /// sink carries the SEVEN codec_event sites (cc:320/:351/:358/:363/
    /// :392 + the two misc sites cc:478/:481 via the cc:441 UDPMiscTests
    /// call).
    #[allow(clippy::collapsible_if)] // literal C nesting kept (the 18g cd_gre.rs:420 precedent, codec.rs:610 lineage)
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut UdpDecodeData,
        netpol: &NetworkPolicy, // cc:367 get_network_policy() seam
        daq: DaqFace,           // cc:264/:420/:271 meta faces (the trio bundle shape)
        sink: QueueSink<'_>,
    ) -> bool {
        let uhlen: u16;                  // cc:315 (C uninitialized decl face; exactly ONE arm assigns on any path — the rustc init-not-mutation face)
        let mut fragmented_udp_flag = false; // cc:316

        // cc:318-:322 the short-dgram guard -> EV 95 + false.
        // vectors:1/:2 `EV 116 95` + `UDP short7 -> 0` (raw 7 < 8).
        if raw.len < u32::from(UDP_HEADER_LEN) {
            codec_event_udp(codec, CodecSid::DECODE_UDP_DGRAM_LT_UDPHDR as u32, sink);
            return false;
        }

        // cc:324-:326 `/* set the ptr to the start of the UDP header
        // */` — the overlay rides raw.data; every field read below
        // goes through the udp.h fns.
        // cc:328 the FIXIT-RC upstream comment rides (literal).
        // cc:329-:346 the uhlen ladder fork:
        if (snort.decode_flags & DECODE_FRAG) == 0 {
            // cc:331 `uhlen = ntohs(udph->uh_len);` — every pinned
            // vectors arm rides this branch (DECODE_FRAG never armed).
            uhlen = udp_len(raw.data);
        } else if snort.is_ip6 {
            // cc:333-:340 the fragmented-ip6 face (NEVER vector-armed
            // but LITERAL): ip_len = get_ip6h()->len() (cc:335), the
            // cc:336-:337 comment rides, uhlen = ip_len MINUS the
            // udph-to-ip_data() distance (cc:338 — folded to the
            // ip_data_udp_off quantity, UdpDecodeData doc):
            let ip_len = ip6_len(snort.ip6h.unwrap_or(&[])); // cc:335
            uhlen = ip_len.wrapping_sub(snort.ip_data_udp_off); // cc:338 (C uint wrap kept)
            fragmented_udp_flag = true; // cc:339
        } else {
            // cc:341-:346 the fragmented-ip4 face: `uhlen = ip4h->len()
            // - ip4h->hlen()` (cc:344; C uint arithmetic assigned to
            // the uint16_t uhlen — the trunc face kept by cast):
            let ip4h = snort.ip4h.unwrap_or(&[]); // cc:343
            // C uint arithmetic assigned to the uint16 uhlen — the
            // WRAPPING subtraction kept literal (every C unsigned pair,
            // skill rule; the trunc on the u16 assignment is the cast):
            uhlen = u32::from(ip4_len(ip4h))
                .wrapping_sub(u32::from(ip4_hlen(ip4h))) as u16;
            fragmented_udp_flag = true; // cc:345
        }

        // cc:348-:353 `/* verify that the header raw.len is a valid
        // value */` -> uhlen < 8 EV 96 + false (vectors:3/:4 `EV 116
        // 96` + `UDP badlen4 -> 0`: uh_len 4).
        if uhlen < u16::from(UDP_HEADER_LEN) {
            codec_event_udp(codec, CodecSid::DECODE_UDP_DGRAM_INVALID_LENGTH as u32, sink);
            return false;
        }

        // cc:355-:365 `/* make sure there are enough bytes ... */`:
        // uhlen > raw.len -> EV 97 (vectors:5/:6 uhlen20: 20 > 12);
        // else-if uhlen < raw.len -> EV 98 (vectors:7/:8 uhlen10:
        // 10 < 12). ONE if / else-if pair, operand per arm (the raw.len
        // C uint32 vs uint16 promotion kept at u32 width).
        if u32::from(uhlen) > raw.len {
            codec_event_udp(codec, CodecSid::DECODE_UDP_DGRAM_SHORT_PACKET as u32, sink);
            return false;
        } else if u32::from(uhlen) < raw.len {
            codec_event_udp(codec, CodecSid::DECODE_UDP_DGRAM_LONG_PACKET as u32, sink);
            return false;
        }

        // cc:367 THE DUAL-FACE GATE (module doc): the policy read AND
        // the daq bypass in one condition; vectors:9 `gate=1` /
        // :10 bypass-TRUE face / :11 offset-mismatch FALSE face.
        if netpol.udp_checksums()
            && !Self::valid_checksum_from_daq(
                daq.pdd,
                DAQ_PKT_DECODE_OFFSET_INVALID, // graft daq.h:15 face
                daq.payload_delta,
            )
        {
            // cc:369-:370 `PegCount* bad_cksum_cnt; bool valid;` — the
            // counter SELECT is the PEG latch (cc:384/:403 selects +
            // cc:410 increment ride the module-doc PEG face, cite-
            // never-land; NO Rust counters — the bad_cksum_cnt local is
            // the SELECT only, never another read).
            let valid: bool;

            if snort.is_ip4 {
                // cc:375-:377 the skip-when-fragmented-or-chk-zero
                // comment rides. cc:379-:383:
                if !fragmented_udp_flag {
                    if udp_raw_chk(raw.data) != 0 {
                        // cc:381 valid_checksum4 (the 0xFFFF probe arm
                        // fails the fold -> vectors:9/:11 dflags=4)
                        valid = Self::valid_checksum4(raw, snort);
                    } else {
                        valid = true; // cc:383
                    }
                } else {
                    valid = true; // cc:383
                }
                // cc:384 bad_cksum_cnt = &stats.bad_ip4_cksum — PEG SELECT
            } else {
                // cc:388-:393 `/* Alert on checksum value 0 for ipv6
                // packets */`: cc:389-:393 (vectors:12/:13 `EV 116
                // 406` + `UDP ip6zero -> 0` — the dflags=4 tail rides
                // the cc:406-:413 arm, NOT the event site; eval-order
                // rule, event-before-mutation kept EXACT, all-decimal
                // face):
                if udp_raw_chk(raw.data) == 0 {
                    valid = false; // cc:391
                    codec_event_udp(codec, CodecSid::DECODE_UDP_IPV6_ZERO_CHECKSUM as u32, sink); // cc:392
                } else if !fragmented_udp_flag {
                    // cc:394-:397 the "(UDP checksum is not optional
                    // in IP6)" comment rides; cc:400:
                    valid = Self::valid_checksum6(raw, codec, snort);
                } else {
                    valid = true; // cc:402
                }
                // cc:403 bad_cksum_cnt = &stats.bad_ip6_cksum — PEG SELECT
            }

            // cc:406-:414 the invalid tail: `!valid && !is_cooked()`
            // gates; the CODEC_UNSURE_ENCAP inner if guards the PEG
            // bump AND the flag write together; the return false rides
            // OUTSIDE the inner if (C shape kept EXACT).
            if !valid && !codec.is_cooked() {
                if (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0 {
                    // cc:410 `(*bad_cksum_cnt)++;` — PEG cite-never-land
                    snort.decode_flags |= DECODE_ERR_CKSUM_UDP; // cc:411
                }
                return false; // cc:413
            }
        }

        // cc:417-:430 the port pair + NAPT face (vectors:14 napt-hit:
        // the probe pins htons(3000)/htons(6000) + ip_layer 0,
        // probe_dec.cc:72, hit cc:421 `codec.ip_layer_cnt == napti->
        // ip_layer` — C u8 == u8 face kept; u32 widening identical).
        let src_port: u16;
        let dst_port: u16;
        if let Some(n) = daq.napt {
            if codec.ip_layer_cnt == n.ip_layer {
                src_port = u16::from_be(n.src_port_be); // cc:423 ntohs (u32 graft slot -> the wire u16 is the C ntohs face on the low 16 bits, face-pinned by probe htons)
                dst_port = u16::from_be(n.dst_port_be); // cc:424
            } else {
                src_port = udp_src_port(raw.data); // cc:428
                dst_port = udp_dst_port(raw.data); // cc:429
            }
        } else {
            // cc:426-:430 the miss/napt-off face (vectors:16 sp=0 dp=0
            // off the all-zero probe ports):
            src_port = udp_src_port(raw.data); // cc:428
            dst_port = udp_dst_port(raw.data); // cc:429
        }

        // cc:432-:438 `/* fill in the printout data structs */` — the
        // four writes + the PktType document pin (cc:433 udph alias:
        // raw.data IS the overlay, UdpDecodeData doc; cc:438
        // set_pkt_type no-home, module doc).
        snort.sp = src_port;                   // cc:434
        snort.dp = dst_port;                   // cc:435
        codec.lyr_len = UDP_HEADER_LEN as u16; // cc:436
        codec.proto_bits |= PROTO_BIT__UDP;    // cc:437

        // cc:440 `// set in packet manager` + the cc:441 misc call —
        // `uhlen - udp::UDP_HEADER_LEN` (the cc:349 guard proves
        // uhlen >= 8: no underflow face exists past the gates).
        self.udp_misc_tests(snort, codec, u32::from(uhlen) - u32::from(UDP_HEADER_LEN), sink);

        // cc:443-:464 THE FOUR-GATE CHAIN — order LITERAL (module doc
        // gate-ORDER FACT: gtp -> teredo -> vxlan -> geneve; the C
        // `and` spellings cc:443/:455/:460 land as && — value-
        // identical operator, deviates nothing).
        if self.config.gtp_decoding()
            && (self.config.is_gtp_port(src_port) || self.config.is_gtp_port(dst_port))
        {
            // cc:446-:448 the inner non-frag guard (frag-udp never gets
            // GTP next — the FIXIT-RC posture):
            if (snort.decode_flags & DECODE_FRAG) == 0 {
                codec.next_prot_id = PROTOCOL_ID_GTP; // cc:447
            }
        } else if is_teredo_port(src_port)
            || is_teredo_port(dst_port)
            || self.config.deep_teredo_inspection()
        {
            // cc:449-:453 the teredo gate (vectors:19 dst 0x0DD8 = BE
            // 3544 -> next 0x0101 = 257):
            codec.next_prot_id = PROTOCOL_ID_TEREDO; // cc:453
        } else if self.config.vxlan_decoding()
            && (self.config.is_vxlan_port(src_port) || self.config.is_vxlan_port(dst_port))
        {
            codec.next_prot_id = PROTOCOL_ID_VXLAN; // cc:458
        } else if self.config.geneve_decoding()
            && (self.config.is_geneve_port(src_port) || self.config.is_geneve_port(dst_port))
        {
            codec.next_prot_id = PROTOCOL_ID_GENEVE; // cc:463
        }

        // cc:466-:467 the tunneled-bits tail.
        if codec.next_prot_id != protocol_id::FINISHED_DECODE {
            codec.proto_bits |= PROTO_BIT__UDP_TUNNELED; // cc:467
        }

        true // cc:469
    }

    /// cc:473-:482 `UDPMiscTests(const DecodeData&, const CodecData&,
    /// uint32_t pay_len)` — the cc:441 call arms it (the C CamelCase
    /// name lands snake_case, cite rides). pay_len > 4000 -> EV 445
    /// (vectors:17/:18 large4020: uh_len 4020 -> pay 4012 > 4000; the
    /// event does NOT flip the return, vectors:18 `-> 1`); sp == 0 ||
    /// dp == 0 -> EV 447 (vectors:15/:16 portzero — the sp/dp reads
    /// off the cc:434-:435 writes).
    fn udp_misc_tests(
        &self,
        snort: &UdpDecodeData,
        codec: &CodecData,
        pay_len: u32,
        sink: QueueSink<'_>,
    ) {
        if pay_len > 4000 {
            // cc:477-:478
            codec_event_udp(codec, CodecSid::DECODE_UDP_LARGE_PACKET as u32, &mut *sink);
        }

        if snort.sp == 0 || snort.dp == 0 {
            // cc:480-:481
            codec_event_udp(codec, CodecSid::DECODE_UDP_PORT_ZERO as u32, sink);
        }
    }

    /// cc:484-:492 out-of-line log. NEVER vectorized (no DEC line calls
    /// log() — the cited-never-vectorized posture, cd_frag.rs:215 /
    /// cd_gre.rs:602 shape; the lyr_len operand UNNAMED cc:485 —
    /// never-read posture): ONE TextLog_Print, THREE args, format
    /// cc:489 `"SrcPort:%d DstPort:%d Len:%d"` — every `%d` decimal;
    /// the Len arg is the `ntohs(udph->uh_len) - udp::UDP_HEADER_LEN`
    /// pair (cc:491, C int arithmetic kept via the i32 widening).
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        // cc:487 the UDPHdr overlay over raw_pkt.
        sink(format!(
            "SrcPort:{} DstPort:{} Len:{}", // cc:489
            udp_src_port(raw_pkt),                                        // cc:490
            udp_dst_port(raw_pkt),                                        // cc:490
            i32::from(udp_len(raw_pkt)) - i32::from(UDP_HEADER_LEN), // cc:491
        ));
    }

    /******************************************************************
     ******************** E N C O D E R  ******************************
     ******************************************************************/

    /// cc:498-:552 encode — NEVER vectorized (no ENC arm in the DEC
    /// probe; literal port-by-reading, every move cited). THE LEFT-
    /// OPEN ip::IpApi face (the 18g/18h IpApiLite-rule lineage):
    /// cd_geneve.rs:477 encode (read THIS pass) carries
    /// `_enc: &mut EncState` and never touches enc's api; udp READS
    /// `enc.ip_api` at cc:525 — this row lands the read as the row-
    /// scoped `UdpApiLite` param (the cd_igmp IpApiLite precedent
    /// family): the is_ip4()/is_ip6() reads + the get_ip4h()/
    /// get_ip6h() wire windows; the producing layer stays OPEN. The
    /// raw_len operand is UNNAMED in C (cc:498) and the Flow* operand
    /// cc:499 likewise — both never-read posture (params carry the
    /// C-shape pin `_raw_len`, Flow dropped like the siblings). cc:501
    /// comment "If we enter this function, this packet is some sort of
    /// tunnel" rides.
    pub fn encode(
        &self,
        raw_in: &[u8], // cc:499 const overlay `hi` cc:506
        _raw_len: u16, // cc:498 UNNAMED never-read operand (C-shape pin)
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
        ip_api: &UdpApiLite, // cc:525 enc.ip_api (left-open seam)
    ) -> bool {
        // cc:503-:504 `if (!buf.allocate(udp::UDP_HEADER_LEN)) return
        // false;` — the NORMAL form (cd_geneve.rs:488 face; NOT the
        // gtp cc:228 inversion).
        if !buf.allocate(u32::from(UDP_HEADER_LEN)) {
            return false;
        }
        // cc:521 hoisted BEFORE the write-face borrow (same quantity:
        // the post-allocate buf.size() feeding the uh_len slot and the
        // cksum walk window; the cd_gre.rs:397 hoist precedence):
        let size = buf.size();

        // cc:506-:507 `hi` over raw_in + `udph_out` over buf.data():
        // in C udph_out ALIASES the allocated window (the Buffer rule)
        // and is written 8 bytes deep; the Rust mirror writes the same
        // 8-byte window, reading ONLY from raw_in (the cc:510 read is
        // `ntohs(hi->uh_dport)` — the IN packet's port, no alias
        // hazard). cc:509 the ports-never-swap-for-geneve comment
        // rides. Wire-slot copy face (the gre_encode memcpy pair):
        if let Some(d) = buf.data_mut()
            && d.len() >= 8
        {
                // cc:512-:513 vs cc:517-:518 the raw uh_sport/uh_dport
                // slot copies (bytes 0-3; the guard cc:510
                // `enc.forward() || is_geneve_port(ntohs(hi->uh_dport))`):
                if enc.forward() || self.config.is_geneve_port(udp_dst_port(raw_in)) {
                    // cc:512 sport = hi->uh_sport / cc:513 dport = hi->uh_dport
                    // (raw uint16 slot copies = 2 wire bytes each; the
                    // get-or-0 face stands ONLY for a hostile short raw_in
                    // where C over-reads — never armed, posture pin):
                    d[0] = *raw_in.first().unwrap_or(&0);
                    d[1] = *raw_in.get(1).unwrap_or(&0);
                    d[2] = *raw_in.get(2).unwrap_or(&0);
                    d[3] = *raw_in.get(3).unwrap_or(&0);
                } else {
                    // cc:517 sport = hi->uh_dport / cc:518 dport = hi->uh_sport
                    d[0] = *raw_in.get(2).unwrap_or(&0);
                    d[1] = *raw_in.get(3).unwrap_or(&0);
                    d[2] = *raw_in.first().unwrap_or(&0);
                    d[3] = *raw_in.get(1).unwrap_or(&0);
                }
                // cc:521-:522 `uh_len = htons(len)` where len (uint16
                // local) = (uint16)buf.size() — the wire slot: the
                // member holds the net-order bits (memory bytes =
                // big-endian 16-bit, the gre wire-write posture;
                // `x.to_be_bytes()` IS the htons store on the LE
                // host). cc:523 `uh_chk = 0`.
                d[4..6].copy_from_slice(&(size as u16).to_be_bytes());
                // cc:535/:546 store a HOST u16 raw into the slot (the
                // gre LE write-back pair): zero is zero both ways.
                d[6] = 0;
                d[7] = 0;

                // cc:525-:547 the checksum pair, re-reading the
                // ALIASED window (C re-derefs udph_out through the
                // overlay — Rust reads the same `d`).
                if ip_api.is_ip4 {
                    // cc:526 is_ip4(): the ps fill cc:530-:534 — cc:534
                    // `ps.hdr.len = udph_out->uh_len` is the RAW-slot
                    // alias read (the udp_raw_len_slot face, NOT the
                    // ntohs formatted face — operand identity kept).
                    let ip4h = ip_api.ip4h.unwrap_or(&[]); // cc:529
                    let ps = Pseudoheader {
                        sip: ip4_sip(ip4h),          // cc:530
                        dip: ip4_dip(ip4h),          // cc:531
                        zero: 0,                     // cc:532
                        protocol: ip_protocol::UDP,  // cc:533
                        len: udp_raw_len_slot(d),    // cc:534 raw alias
                    };
                    // cc:535 `udph_out->uh_chk = udp_cksum(udph_out,
                    // len, ps)` — the walk window len = the cc:521
                    // uint16 local == buf.size(); the store is the raw
                    // uint16 slot (LE write-back face, the gre
                    // chksum-bytes precedent; NEVER vector-armed —
                    // deviations note, no ENC vector).
                    let w = udp_cksum4(d, usize::from(size as u16), ps);
                    d[6..8].copy_from_slice(&w.to_le_bytes());
                } else if ip_api.is_ip6 {
                    // cc:537 is_ip6(): cc:541-:542 the memcpy over
                    // u6_addr8 = the 16 address BYTES verbatim (the
                    // ip6_addr_words stored-bytes face); cc:543-:545
                    // zero/protocol/len (cc:545 again the RAW alias
                    // udph_out->uh_len); cc:546 store face as above.
                    let ip6h = ip_api.ip6h.unwrap_or(&[]); // cc:540
                    let ps6 = Pseudoheader6 {
                        sip: ip6_addr_words(ip6h, 8),  // cc:541 (bytes 8-23)
                        dip: ip6_addr_words(ip6h, 24), // cc:542 (bytes 24-39)
                        zero: 0,                       // cc:543
                        protocol: ip_protocol::UDP,    // cc:544
                        len: udp_raw_len_slot(d),      // cc:545 raw alias
                    };
                    let w = udp_cksum6(d, usize::from(size as u16), ps6);
                    d[6..8].copy_from_slice(&w.to_le_bytes()); // cc:546 raw slot face
                }
                // cc:547 no else arm (literal).
        }

        // cc:549-:550 the enc writes (landed home ip_protocol::UDP =
        // 17; ETHERTYPE_NOT_SET = 0 the codec.rs home).
        enc.next_proto = ip_protocol::UDP;
        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET;
        true // cc:551
    }

    /// cc:554-:589 update — NEVER vectorized, literal: the cc:557
    /// UDPHdr overlay h = raw_pkt; cc:559 `updated_len += sizeof(*h)`
    /// (sizeof(UDPHdr) = 8 = the four uint16 slots udp.h:33-:36 — the
    /// uint32 ref accumulate kept WRAPPING, the lineage pair rule);
    /// cc:560 `h->uh_len = htons((uint16_t) updated_len)` the BE-at-
    /// rest slot. cc:562 the `(flags & UPD_COOKED) == 0 ||
    /// (flags & UPD_REBUILT_FRAG) != 0` guard (the landed
    /// UPD_COOKED/UPD_REBUILT_FRAG homes, codec.rs:83/:87 face —
    /// UpdateFlags u8 widened to the EncodeFlags u64 param); cc:564
    /// chk = 0; the cc:566-:587 ip4/ip6 pseudoheader pair — SAME seam
    /// reads as encode (get_ip4h() cc:569 / get_ip6h() cc:580) but
    /// cc:574/:585 `htons((uint16_t)updated_len)` (NOT the raw alias —
    /// operand identity per arm) and the raw-slot chk stores cc:575/
    /// :586 walked over (h, updated_len). The ip::IpApi operand rides
    /// UdpApiLite (the encode ruling); lyr_len UNNAMED cc:555 (the
    /// _lyr_len shape pin).
    pub fn update(
        &self,
        ip_api: &UdpApiLite, // cc:554 const ip::IpApi& (left-open seam)
        flags: EncodeFlags, // cc:555 const EncodeFlags
        raw_pkt: &mut [u8], // cc:555 uint8_t* raw_pkt
        _lyr_len: u16,      // cc:555 uint16_t /*lyr_len*/ UNNAMED
        updated_len: &mut u32, // cc:555 uint32_t& reference param
    ) {
        // cc:559 the += sizeof(UDPHdr)==8 accumulate (udp.h:31-:62 the
        // struct face; wrapping — every C unsigned pair, skill rule):
        *updated_len = updated_len.wrapping_add(8);
        // cc:560 uh_len = htons trunc face (the uint32 -> uint16 cast
        // load-bearing, kept; memory bytes = wire BE — see the encode
        // cc:522 cite for the htons-store face):
        if raw_pkt.len() >= 6 {
            raw_pkt[4..6].copy_from_slice(&(*updated_len as u16).to_be_bytes());
        }

        if (flags & u64::from(UPD_COOKED)) == 0 || (flags & u64::from(UPD_REBUILT_FRAG)) != 0 {
            // cc:564 h->uh_chk = 0:
            if raw_pkt.len() >= 8 {
                raw_pkt[6] = 0;
                raw_pkt[7] = 0;
            }

            if ip_api.is_ip4 {
                // cc:566-:576 (ps.hdr.len cc:574 = the FRESH htons,
                // the contrast against encode cc:534 kept; chk store
                // cc:575 over (h, updated_len) — the declared-walk
                // posture checksum.rs:175-:179; short-window faces =
                // the never-armed C face, get-bounded stands in):
                let ip4h = ip_api.ip4h.unwrap_or(&[]); // cc:569
                let ps = Pseudoheader {
                    sip: ip4_sip(ip4h),                // cc:570
                    dip: ip4_dip(ip4h),                // cc:571
                    zero: 0,                           // cc:572
                    protocol: ip_protocol::UDP,        // cc:573
                    len: u16::to_be(*updated_len as u16), // cc:574 htons
                };
                let w = udp_cksum4(raw_pkt, *updated_len as usize, ps);
                if raw_pkt.len() >= 8 {
                    raw_pkt[6..8].copy_from_slice(&w.to_le_bytes()); // cc:575 raw slot
                }
            } else if ip_api.is_ip6 {
                // cc:577-:587 — cc:581-:582 the memcpy over
                // u6_addr32 word slots (the ip6_addr_words face; SAME
                // 16 bytes as the encode u6_addr8 arm, operand
                // identity between the two arms kept):
                let ip6h = ip_api.ip6h.unwrap_or(&[]); // cc:580
                let ps6 = Pseudoheader6 {
                    sip: ip6_addr_words(ip6h, 8),      // cc:581
                    dip: ip6_addr_words(ip6h, 24),     // cc:582
                    zero: 0,                           // cc:583
                    protocol: ip_protocol::UDP,        // cc:584
                    len: u16::to_be(*updated_len as u16), // cc:585 htons
                };
                let w = udp_cksum6(raw_pkt, *updated_len as usize, ps6);
                if raw_pkt.len() >= 8 {
                    raw_pkt[6..8].copy_from_slice(&w.to_le_bytes()); // cc:586 raw slot
                }
            }
            // cc:587 the cc:562 guard's closing brace; no else arm.
        }
    }

    /// cc:591-:606 format — NEVER vectorized, literal: the reverse arm
    /// cc:595-:600 exchanges the RAW uh_sport/uh_dport uint16 slots
    /// via the tmp_port LOCAL (the two-slot byte-window swap fold —
    /// bytes 0-1 <-> 2-3, no ntohs round-trip in C: raw slots swap);
    /// then cc:602 the udph alias document pin, cc:603-:604 the sp/dp
    /// BE port reads, cc:605 set_pkt_type document-only (all faces per
    /// the UdpDecodeData doc).
    pub fn format(&self, reverse: bool, raw_pkt: &mut [u8], snort: &mut UdpDecodeData) {
        // cc:593 the UDPHdr overlay over raw_pkt.
        if reverse {
            // cc:597-:599 `uint16_t tmp = uh_sport; uh_sport =
            // uh_dport; uh_dport = tmp;` (the short-buffer face never
            // armed — C assumes the 4-byte window; bounded stand-in):
            if raw_pkt.len() >= 4 {
                raw_pkt.swap(0, 2);
                raw_pkt.swap(1, 3);
            }
        }
        snort.sp = udp_src_port(raw_pkt); // cc:603
        snort.dp = udp_dst_port(raw_pkt); // cc:604
        // cc:605 `snort.set_pkt_type(PktType::UDP)` — document-only
        // face (decode_data.h:45-:48, no landed Rust home — module doc).
    }
}

/// The encode/update LEFT-OPEN ip::IpApi read seam (module doc): the
/// cc:525 `enc.ip_api` read and the cc:554 update operand. Names
/// mirror the C call sites (the cd_igmp.rs IpApiLite family posture):
/// is_ip4() cc:526/:566, is_ip6() cc:537/:577, get_ip4h() cc:529/:569,
/// get_ip6h() cc:540/:580. WHO feeds these stays OPEN (the ip codec
/// rows); NOT a full IpApi port.
#[derive(Copy, Clone, Default)]
pub struct UdpApiLite {
    pub is_ip4: bool,                // cc:526/:566
    pub is_ip6: bool,                // cc:537/:577
    pub ip4h: Option<&'static [u8]>, // cc:529/:569
    pub ip6h: Option<&'static [u8]>, // cc:540/:580
}

/// The codec_event sites ride the LANDED framework/codec.rs
/// codec_event (GID_DECODE 116 -> the vectors `EV 116 <sid>` family,
/// the cd_gre.rs:626-631 shape).
#[inline]
fn codec_event_udp(codec: &CodecData, sid: u32, sink: QueueSink) {
    crate::framework::codec::codec_event(codec, sid, sink);
}

// cc:612-:613 `static Module* mod_ctor() { return new UdpModule; }` +
// cc:615-:616 `static void mod_dtor(Module* m) { delete m; }` — the
// mod pair is SET (vectors_faceA:7 `udp mod_ctor=1 mod_dtor=1`, the
// record slots cc:641-:642; the Rust mod_ctor face is UdpModule::new,
// the dtor the stack-owned drop, 18d posture). The codec ctor/dtor
// pair cc:618-:628 lands as `ctor()` below (the mod-optional config
// face cc:621-:623 with its "Codecs can be instantiated without
// modules. In which case use the snort defaults for config." comment
// riding — the probe's ua->ctor(nullptr), probe_dec.cc:46, is the
// None arm) + cc:627-:628 dtor = the Box drop face.

/// cc:618-:625 `static Codec* ctor(Module* m)` — cc:620-:621 the
// static_cast + cc:623 `mod ? mod->get_data() : new UdpCodecConfig()`
// + cc:624 `new UdpCodec(cfg)`. The C nullptr-config UB face (mod set
// but begin() never called -> get_data() nullptr -> cc:237 stores it,
// decode deref crashes) is NEVER armed — the witness always begins
// before any ctor-with-mod; the defined Rust stand-in falls through
// to the default config there (the lineage defined-stand-in posture).
pub fn ctor(module: Option<&mut UdpModule>) -> Box<UdpCodec> {
    let cfg = match module {
        Some(m) => m.get_data().unwrap_or_else(UdpCodecConfig::new), // cc:623 get_data() (stand-in note above)
        None => UdpCodecConfig::new(), // cc:623 the snort-defaults arm
    };
    Box::new(UdpCodec::new(Box::new(cfg))) // cc:624
}

/// cc:630-:650 `static const CodecApi udp_api` — THE true-name record
/// (the C struct identifier `udp_api` cc:630 -> UDP_API, the cd_auth
/// AH_API precedent; print faces name=udp both faces, no drift this
/// TU). vectors_faceA:5 `API udp type=0 size=112 ver=1900547
/// name=udp` + :6 `HELP udp support for user datagram protocol` + :7
/// `udp mod_ctor=1 mod_dtor=1` (mod pair SET, the trio-uniform arm).
pub const UDP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:633
    size: CDAPI_SIZEOF_CODEC_API, // cc:634 sizeof(CodecApi) = 112 (probe pin)
    api_version: CDAPI_VERSION,   // cc:635 1900547
    version: 0,                   // cc:636
    features: PLUGIN_SO_RELOAD,   // cc:637
    options: API_OPTIONS,         // cc:638
    name: CD_UDP_NAME,            // cc:639
    help: CD_UDP_HELP,            // cc:640
    mod_ctor: true,               // cc:641 SET
    mod_dtor: true,               // cc:642 SET
    pinit: false,                 // cc:644 nullptr // pinit
    pterm: false,                 // cc:645 nullptr // pterm
    tinit: false,                 // cc:646 nullptr // tinit
    tterm: false,                 // cc:647 nullptr // tterm
    ctor: true,                   // cc:648 ctor
    dtor: true,                   // cc:649 dtor
};

/// cc:652-:660 the table — the BUILDING_SO ternary face (cc:652-:653
/// `#ifdef BUILDING_SO` SO_PUBLIC arm / cc:655 the REAL live internal
/// arm `const BaseApi* cd_udp[] =`), feeding `&udp_api.base` cc:658 +
/// the nullptr terminator cc:659 folding onto the slice length (18c
/// fold). The extern ladder "cd_udp" is ALREADY resident
/// codec_api.rs:128 — the dormant extern stays a record, not a link
/// edge.
pub const CD_UDP: CodecTable = &[&UDP_API];
