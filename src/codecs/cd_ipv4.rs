//! Port of `src/codecs/ip/cd_ipv4.cc` (790 L) — row 20a, the head TU of
//! the `tools/ipheavy_harness` ZERO-gate probe-only chapter. Ground:
//! snort3-src @ fe29cbe, md5 `def01f1df71ab250896da1764f6c0f92`, wc 790
//! (both re-measured THIS pass: `md5sum` + `wc -l` on the ground TU).
//! DIR FACT: `codecs/ip/` (cc:25-:43 include face: `<daq.h>` `<daq_dlt.h>`
//! `<random>` + codec_module.h / codec.h / log_text.h / messages.h /
//! snort_config.h / parse_ip.h / ip.h / ipv4.h / ipv4_options.h / tcp.h /
//! sf_ipvar.h / util.h / checksum.h). THE 26th straight honest zero-gate
//! face: TEST_CASE/CppUTest grep EXACTLY-0 in the TU (re-run THIS pass) +
//! link/test find-0 + add_cpputest 0 — the ipheavy vectors pair Rust
//! mirrors against the LIVE C build.
//!
//! TRUE NAME holds this TU: file base == table name `cd_ipv4[]` at cc:785
//! (REAL BUILDING_SO split :782-:786: SO arm `snort_plugins[]` :783 /
//! static-build `const BaseApi* cd_ipv4[] =` :785), nm D EXACTLY-1 ==
//! FILE base (the equality-pin law; ONE feed `&ipv4_api.base` :788 +
//! nullptr :789 -> faceA LOADS 1). api struct `ipv4_api` cc:760 (lands
//! IPV4_API — the cd_auth.rs AH_API = C-struct-name rule). NAME/HELP at
//! the DISK lines :47/:48/:49: HELP is the ADD_DLT splice (codec.h:52
//! macro face, the cd_eth.rs:58 precedent) -> the string
//! `"support for Internet protocol v4 (DLT 228)"` — the 228 = SYNTHETIC
//! ext#4 daq_dlt.h DLT_IPV4 CITE face (the daq3 graft family; NEVER ABI
//! truth, plan row 20 re-cites the real SDK).
//!
//! PEGS cite-never-land (cc:53-:58 PegInfo/Stats/THREAD_LOCAL + the
//! get_pegs/get_counts overrides cc:103-:107): the TWO rows ride THIS
//! comment — CountType::SUM `bad_checksum` "nonzero ip checksums" (cc:55)
//! / SUM `checksum_bypassed` "checksum calculations bypassed" (cc:56);
//! `struct Stats { PegCount bad_cksum; PegCount cksum_bypassed; }`
//! cc:60-:64 + `static THREAD_LOCAL Stats stats;` cc:66. The cc:146
//! cksum_bypassed select and the cc:269 bad_cksum increments are PEG
//! cite-never-land faces (cd_udp/:37 + cd_icmp4 precedent; counters
//! NEVER printed by any vector). NO Rust counter machinery lands.
//!
//! THE DAQ SEAM (ext#4 SYNTHETIC, NEVER ABI truth — the cd_udp.rs:18-:37
//! graft ruling carried): the DAQ SDK header is ABSENT ground-side; the
//! harness graft copy/daq.h shapes are drawn ONLY from the measured call
//! faces cc:135-:144 (DAQ_PktDecodeData_t `flags.bits.l3_checksum/.ipv4/
//! .l3` + `l3_offset` — the cc:137 guard reads EXACTLY these three bits,
//! the l3-vs-l4 twin face of cd_icmp4 DaqPdd) + cc:245-:251
//! (DAQ_NAPTInfo_t `ip_layer/src_addr/dst_addr` + the src/dst
//! addr_family accessors). THE offset sentinel `DAQ_PKT_DECODE_OFFSET_
//! INVALID (-1)` rides row-scoped w/ the cd_icmp4.rs:149 landed twin
//! cite (dup-not-import family); the cc:143 pointer difference
//! `raw.data - daq_msg_get_data(raw.daq_msg)` folds to the explicit
//! `payload_delta: i64` param (cd_icmp4 DaqFace precedent — pointer math
//! probe-faked). `valid_checksum_from_daq` lands VERBATIM statement-for-
//! statement (cc:133-:148), the `stats.cksum_bypassed++` :146 leg is the
//! PEG face above.
//!
//! THE sfvar WITNESS FACE (cc:67): `static sfip_var_t* MulticastReservedIp
//! = nullptr` — ginit :727-:730 fills it via `sfip_var_from_string(...)`
//! and the cc:732 assert is the NDEBUG elide face; at the harness face
//! witness_ipvars.cc pins `sfip_var_from_string` -> nullptr, so the
//! cc:407/:410 legs `sfvar_ip_in(MulticastReservedIp, ...)` measure
//! FALSE (NDEBUG skips the asserts). THE FOLD: `sfvar_in = false` (the
//! witness face cited at the use sites) + the `msb == IP4_RESERVED` arm
//! stays REAL. `src/sfip/sf_ipvar.rs` is NEVER imported (the fold needs
//! zero sf_ipvar surface; the ginit STRING LIST rides the tail comment
//! verbatim with cites).
//!
//! WORDS_BIGENDIAN cc:379-:385: the BE arms `ip_src >> 24` :380-:381 are
//! CITED NEVER landed (host LE, x86 build face); the `#else` LE host arms
//! `ip_src & 0xff` :383-:384 LAND — probe-pinned (the s_addr wire-order
//! face cd_udp.rs:568-:580 ip4_sip/ip4_dip twin: the LE u32 of header
//! bytes 12-15 / 16-19).
//!
//! THE `#if 0` DEAD BLOCK :210-:217 (`else if (ip_len < len)` — "There is
//! no need to alert when (ip_len < len)"): cited NEVER landed (the R
//! dead-face census; the block text rides the cc:203 gate comment).
//!
//! THE IP API SEAM: cc:225-:240 read `snort.ip_api.is_ip6()/is_ip4()` —
//! the PREVIOUS layer's IpApi::Type (ip.h:38 `enum Type { IAT_NONE,
//! IAT_4, IAT_6, IAT_DATA }`, is_ip6/is_ip4 inline faces ip.h:77-:81).
//! The row-scoped Ipv4DecodeData seam (cd_icmp4.rs:177-:197 IpApiLite/
//! Icmp4DecodeData precedent) carries decode_flags, src/dst SfIp (the
//! cc:243 set + cc:248-:252 update operands, SfIp::set_raw RESIDENT
//! sf_ip.rs:583-:596 — the v4-mapped 0xffff ip8 prefix face) + an `ip_type`
//! IAT slot (the cc:225/:233 read legs; set(iph) writes IAT_4 at cc:243,
//! ip.h set -> type = IAT_4) + `pkt_type` (the cc:336 set_pkt_type face,
//! decode_data.h:192-:193; PktType::IP ordinal 1, decode_data.h:45-:48 —
//! the cd_icmp4 PKT_TYPE__ICMP h:45-:48 precedent). The REAL IpApi owner
//! (ip.h:36-:110 + ip.cc set/update) stays LEFT-OPEN — NEVER ported.
//!
//! sid census (ALL 21 ipv4_rules rows + the 6 extra decode sids RESIDENT
//! codec_module.rs, ZERO new constants): NOT_IPV4_DGRAM 1 (:69, h:46) /
//! INVALID_HEADER_LEN 2 (:70, h:47) / DGRAM_LT_IPHDR 3 (:71, h:48) /
//! IPV4OPT_BADLEN 4 (:72, h:49) / IPV4OPT_TRUNCATED 5 (:73, h:50) /
//! DGRAM_GT_CAPLEN 6 (:74, h:51) / ZERO_TTL 404 (:77) / BAD_FRAGBITS 405
//! (:78) / IP4_LEN_OFFSET 407 (:79) / SRC_THIS_NET 408 (:80) /
//! DST_THIS_NET 409 (:81) / SRC_MULTICAST 410 (:82) / SRC_RESERVED 411
//! (:83) / DST_RESERVED 412 (:84) / SRC_BROADCAST 413 (:85) /
//! DST_BROADCAST 414 (:86) / MIN_TTL 428 (:87 — TABLE-ONLY: no decode
//! site fires it THIS TU) / DF_OFFSET 430 (:88) / RESERVED_FRAG_BIT 448
//! (:89) / IP_OPTION_SET 444 (:90) / IP4_HDR_TRUNC 425 (:91) + the extra
//! decode events MULTIPLE_ENCAPSULATION 293 (cc:175) / BAD_TRAFFIC_
//! SAME_SRCDST 151 (cc:367) / BAD_TRAFFIC_LOOPBACK 150 (cc:389) /
//! ICMP_DOS_ATTEMPT 452 (cc:449/:468/:473 — the OPTIONS vuln, "Yes, it's
//! an ICMP-related vuln in IP options" :418) / ZERO_LENGTH_FRAG 459
//! (cc:326) / IP_UNASSIGNED_PROTO 449 (cc:351). Table face: 22 rows ->
//! `{ 0, nullptr }` terminator :92 (21 data + 1 term).
//!
//! GATE-ORDER FACT (EVERY cc cite rides decode verbatim): the :166 short
//! gate BEFORE :173 maxlayers BEFORE :179 ++ip_layer_cnt BEFORE :187
//! ver!=4 BEFORE :197 hlen BEFORE :203 ip_len>raw.len (the `#if 0`
//! :210-:217 dead else-if rides CITED) BEFORE :219 ip_len<hlen BEFORE
//! the :225-:240 tunnel fork BEFORE the :243 ip_api.set BEFORE :245-:253
//! NAPT BEFORE :258 IP4AddrTests (the addr events fire BEFORE the
//! checksum arm — vectors pin the EV order) BEFORE :260 gate
//! `get_network_policy()->ip_checksums()` (policy.h:202 inline face +
//! the NSDMI :233 `checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__
//! DEF` witness 1 face — folded to `conf.ip_checksums: bool = true`, the
//! landed twin posture of NetworkPolicy::ip_checksums, policy.rs:201)
//! BEFORE :277 IPOPT_FLAGS clear BEFORE :280 decode-opts BEFORE :284 the
//! const_cast raw.len mutation (LANDS AS A LOCAL COPY — never mutate the
//! caller; probe never re-reads raw.len after, honest fold) BEFORE
//! :288-:334 the frag ladder BEFORE :336/:337 BEFORE :338 MiscTests
//! BEFORE :340 lyr_len BEFORE :341/:342 the ip6 clears BEFORE :346-:354
//! the next-prot gate.
//!
//! THE TUNNEL-MASK WITNESS MODEL (witness_18f observable-mask face,
//! carried from cd_vxlan/cd_geneve/cd_mpls): `tunnel_bypass_enabled` is
//! SYNTHETIC-folded as `(conf.tunnel_mask & proto) == 0` — mask 0 ->
//! bypass ON, bit set -> bypass off; the call sites cc:230 (TUNNEL_4IN6
//! 0x08, snort_config.h:122) / cc:238 (TUNNEL_4IN4 0x10, :123). The C
//! decl `SO_PUBLIC bool tunnel_bypass_enabled(uint16_t proto) const`
//! snort_config.h:777 stays OUT-OF-LINE-CITED; no Rust provider lands.
//! THE maxlayers face: `hit_ip_maxlayers(curr) = max_ip_layers && (curr
//! >= max_ip_layers)` snort_config.h:454-:455 (the "curr_ip is the zero
//! based ip layer" comment :453) + NSDMI `max_ip_layers = 0` :279 (the
//! default NEVER arms the :173 gate); `address_anomaly_check_enabled =
//! > false` NSDMI :282 + the inline read face :500-:501.
//!
//! mod arms ALL REAL (the faceA `ipv4 mod_ctor=1 mod_dtor=1` + the t-arm
//! PIN faceA `ipv4 tinit=1 tterm=1`): mod_ctor :718-:719 / mod_dtor
//! :721-:722 SET; pinit/pterm = ipv4_codec_ginit/:724-:733 (the multicast
//! reserved string list :727-:730 lands as a CITED comment — the
//! sfip_var_from_string witness nullptr face above) + gterm :735-:741;
//! tinit :743-:746 (`thread_rand = new std::mt19937(...)` — the mt19937
//! encode era, cite-never-land) + tterm :748-:752; ctor :754-:755 `ctor
//! (Module*)` IGNORES Module (the DRIFT cite vs cd_mpls :347-:355 config-
//! threading — no Ipv4Codec config exists); dtor :757-:758 SET. THE log/
//! encode/update/format world stays CITE-NEVER-LAND (the ip-family
//! lineage; bodies transcribed in the tail comments, ZERO stub-callable
//! fns land for them — see the L O G G E R / E N C O D E R tails).

use crate::codecs::checksum::ip_cksum;
use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CODEC_DF, CODEC_IPOPT_FLAGS,
    CODEC_IPOPT_LEN_THREE, CODEC_IPOPT_RR_SEEN, CODEC_IPOPT_RTRALT_SEEN, CODEC_NON_IP_TUNNEL,
    CODEC_UNSURE_ENCAP, CodecApiRecord, CodecData, CodecTable, PT_CODEC, PLUGIN_SO_RELOAD,
    ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;
use crate::sfip::sf_ip::SfIp;
use crate::sfip::sf_returns::AF_INET; // sf_returns.rs:29 `AF_INET: i16 = 2` (RESIDENT)

/// :47 `#define CD_IPV4_NAME "ipv4"` (the :113 Codec(name) + :769 api slot).
pub const CD_IPV4_NAME: &str = "ipv4";
/// :48 `#define CD_IPV4_HELP_STR "support for Internet protocol v4"`.
pub const CD_IPV4_HELP_STR: &str = "support for Internet protocol v4";
/// :49 `#define CD_IPV4_HELP ADD_DLT(CD_IPV4_HELP_STR, DLT_IPV4)` — the
/// codec.h:52 compile-time splice (the cd_eth.rs:58 ladder precedent):
/// `CD_IPV4_HELP_STR " (DLT " #dlt ")"` -> the SPLICED string with the
/// SYNTHETIC ext#4 daq_dlt.h DLT_IPV4 228 (CITE face, NEVER ABI truth).
pub const CD_IPV4_HELP: &str = "support for Internet protocol v4 (DLT 228)";

/// ext#4 graft daq_dlt face `DLT_IPV4 = 228` — the :152
/// get_data_link_type emplace + the :49 HELP splice subject. SYNTHETIC
/// (the daq3 graft family; the cd_eth.rs:47-:48 DLT_EN10MB/DLT_PPP_ETHER
/// landed twins show the row-scoped DLT home).
pub const DLT_IPV4: i32 = 228;

/// graft copy/daq.h `#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)` — the
/// :140 sentinel compare `pdd->l3_offset != DAQ_PKT_DECODE_OFFSET_
/// INVALID`. Row-scoped twin of the cd_icmp4.rs:145-:149 landed face
/// (dup-not-import family). SYNTHETIC graft face, NEVER ABI truth.
pub const DAQ_PKT_DECODE_OFFSET_INVALID: i64 = -1;

/// snort_config.h:122 `TUNNEL_4IN6 = 0x08` (the :230 bypass call arg;
/// the cd_vxlan/cd_geneve/cd_mpls TUNNEL_* row-scoped sibling family).
pub const TUNNEL_4IN6: u16 = 0x08;
/// snort_config.h:123 `TUNNEL_4IN4 = 0x10` (the :238 bypass call arg).
pub const TUNNEL_4IN4: u16 = 0x10;

/// ipv4.h:30 `#define IP_MAXPACKET 65535` — the :318 LEN_OFFSET gate.
pub const IP_MAXPACKET: u32 = 65535;
/// ipv4.h:37 `constexpr uint32_t IP4_BROADCAST = 0xffffffff` — the
/// :103-:107 is_src/is_dst_broadcast compares (RAW u32 field face).
pub const IP4_BROADCAST: u32 = 0xffffffff;
/// ipv4.h:38 `constexpr uint8_t IP4_HEADER_LEN = 20` — the :166 short
/// gate, :197 hlen gate, :278 opt-len base, :338 MiscTests arg.
pub const IP4_HEADER_LEN: u8 = 20;
/// ipv4.h:39 `constexpr uint8_t IP4_THIS_NET = 0x00; // msb`.
pub const IP4_THIS_NET: u8 = 0x00;
/// ipv4.h:40 `constexpr uint8_t IP4_MULTICAST = 0x0E; // ms nibble`.
pub const IP4_MULTICAST: u8 = 0x0E;
/// ipv4.h:41 `constexpr uint8_t IP4_RESERVED = 0x0F; // ms nibble`.
pub const IP4_RESERVED: u8 = 0x0F;
/// ipv4.h:42 `constexpr uint8_t IP4_LOOPBACK = 0x7F; // msb`.
pub const IP4_LOOPBACK: u8 = 0x7F;

/// decode_data.h:131 `DECODE_ERR_CKSUM_IP = 0x00000001` (the :270 write;
/// row-scoped home — cd_udp DECODE_FRAG :168-style dup-not-import twin).
pub const DECODE_ERR_CKSUM_IP: u64 = 0x0000_0001;
/// decode_data.h:141 `DECODE_FRAG = 0x00000040` (the :328/:331 write +
/// :346 read; dup-not-import twin of the cd_frag.rs:80 / cd_udp.rs:168
/// landed faces — the landed family re-homes AT this row).
pub const DECODE_FRAG: u64 = 0x0000_0040;
/// decode_data.h:142 `DECODE_MF = 0x00000080` (the :307 write, :322/:333
/// reads; cd_frag.rs:82 twin).
pub const DECODE_MF: u64 = 0x0000_0080;
/// decode_data.h:143 `DECODE_DF = 0x00000100` (the :303 write; row home).
pub const DECODE_DF: u64 = 0x0000_0100;

/// decode_data.h:45-:48 `enum class PktType : std::uint8_t { NONE, IP,
/// ... }` -> IP ordinal 1 — the :336 `snort.set_pkt_type(PktType::IP)`
/// feed (the cd_icmp4.rs:140 PKT_TYPE__ICMP h:45-:48 precedent).
pub const PKT_TYPE__IP: u8 = 1;

/// ip.h:38 `enum Type { IAT_NONE, IAT_4, IAT_6, IAT_DATA }` — ordinals
/// 0/1/2/3; the Ipv4DecodeData `ip_type` seam face read by :225
/// is_ip6() (ip.h:77) / :233 is_ip4() (ip.h:80) BEFORE the :243 set.
pub const IAT_NONE: u8 = 0; // ip.h:38 1st
pub const IAT_4: u8 = 1; // ip.h:38 2nd
pub const IAT_6: u8 = 2; // ip.h:38 3rd
pub const IAT_DATA: u8 = 3; // ip.h:38 4th (never set/read at this TU's sites)

/// tcp.h:76 `constexpr int OPT_TRUNC = -1` — :521/:529/:540 (the IP
/// option decoder REUSES the TCP opts, "Yes, we use TCP_OPT_* for the IP
/// option decoder" :537).
pub const OPT_TRUNC: i32 = -1;
/// tcp.h:77 `constexpr int OPT_BADLEN = -2` — :525/:538.
pub const OPT_BADLEN: i32 = -2;

/// ipv4_options.h:33-:46 `enum class IPOptionCodes : std::uint8_t` — the
/// FULL enum list cited (EOL 0x00 :34 / NOP 0x01 :35 / RR 0x07 :36 /
/// TS 0x44 :37 / SECURITY 0x82 :38 / LSRR 0x83 :39 / LSRR_E 0x84 :40 /
/// ESEC 0x85 :41 / SATID 0x88 :42 / SSRR 0x89 :43 / RTRALT 0x94 :44 /
/// ANY 0xff :45); THIS TU touches EXACTLY FIVE (the two switch label
/// stacks :430-:477 + :497-:513) — those five land as consts below, the
/// seven untouched arms ride this cite (the cd_icmp4 touched-census rule).
pub const IPOPT_EOL: u8 = 0x00; // h:34 — :430/:497
pub const IPOPT_NOP: u8 = 0x01; // h:35 — :505 (MiscTests default rides NOP)
pub const IPOPT_RR: u8 = 0x07; // h:36 — :434/:513
pub const IPOPT_TS: u8 = 0x44; // h:37 — :453
pub const IPOPT_RTRALT: u8 = 0x94; // h:44 — :509

/// The ext#4 SYNTHETIC `DAQ_PktDecodeData_t` field face (graft copy/daq.h
/// shapes MEASURED from the :135-:144 use sites, NEVER ABI): the :137
/// guard reads bitfield arms `flags.bits.l3_checksum`, `.ipv4`, `.l3` +
/// the `int32_t l3_offset` sentinel read :140/:143 (the cd_icmp4.rs:160
/// DaqPdd l4-family twin — THIS TU reads l3).
#[derive(Copy, Clone, Default)]
pub struct Ipv4Pdd {
    pub l3_checksum: bool, // :137
    pub ipv4: bool, // :137
    pub l3: bool, // :137
    pub l3_offset: i64, // :140/:143
}

/// The ext#4 SYNTHETIC `DAQ_NAPTInfo_t` field face (:245-:251 use sites,
/// NEVER ABI truth): `ip_layer` (:246 compare), `src_addr`/`dst_addr`
/// (:250/:251 set feeds, raw u32 network-order) + the
/// `daq_napt_info_src_addr_family(napti)` / `..._dst_addr_family(...)`
/// accessor faces (:250/:251 fam args).
#[derive(Copy, Clone, Default)]
pub struct Ipv4NaptFace {
    pub ip_layer: u8, // :246
    pub src_addr: u32, // :250
    pub dst_addr: u32, // :251
    pub src_addr_family: u16, // :250 accessor face
    pub dst_addr_family: u16, // :251 accessor face
}

/// The decode-call DAQ parameter bundle (cd_icmp4.rs:173-:177 DaqFace
/// shape): the two valid_checksum_from_daq legs + the NAPT meta leg +
/// the probe-faked `raw.data - daq_msg_get_data(raw.daq_msg)` delta (:143).
#[derive(Copy, Clone, Default)]
pub struct Ipv4DaqFace {
    pub pdd: Option<Ipv4Pdd>, // :135-:136 (None == the getter nullptr)
    pub napt: Option<Ipv4NaptFace>, // :245 (None == the getter nullptr)
    pub payload_delta: i64, // :143 pointer-delta fold
}

/// The config seam for the THREE config faces this TU reads (the C reads
/// them off `codec.conf` / `SnortConfig::get_conf()` / the
/// `snort::get_network_policy()` free fn — the landed fold keeps ONE
/// Copy struct at the decode boundary):
/// - `max_ip_layers` NSDMI `= 0` snort_config.h:279 (the :173 gate leg),
/// - `address_anomaly_check_enabled` NSDMI `= false` :282 (the :405 gate;
///   the inline read face :500-:501),
/// - `ip_checksums` the policy.h:202-:203 `(checksum_eval &
///   CHECKSUM_FLAG__IP) != 0` inline over the NSDMI :233 ALL|DEF default
///   -> TRUE at the witness face (the policy.rs:201 landed twin face),
/// - `tunnel_mask` the SYNTHETIC witness_18f observable-mask model of
///   tunnel_bypass_enabled (snort_config.h:777 out-of-line decl; module
///   doc), default 0 == bypass ON everywhere the :230/:238 arms run.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Conf {
    pub max_ip_layers: u8, // snort_config.h:279 NSDMI 0
    pub address_anomaly_check_enabled: bool, // snort_config.h:282 NSDMI false
    pub ip_checksums: bool, // policy.h:202 + :233 NSDMI face (witness TRUE)
    pub tunnel_mask: u16, // witness_18f mask face (module doc)
}

/// THE NSDMI FACE — a derived Default would land ip_checksums FALSE and
/// SKIP the :260 checksum gate the vectors pin; hand-written per the
/// snort_config.h NSDMIs + the policy.h:233 ALL|DEF witness face.
impl Default for Ipv4Conf {
    fn default() -> Self {
        Ipv4Conf {
            max_ip_layers: 0, // snort_config.h:279
            address_anomaly_check_enabled: false, // snort_config.h:282
            ip_checksums: true, // policy.h:233 (ALL|DEF -> ip_checksums TRUE)
            tunnel_mask: 0, // witness_18f (bypass ENABLED at the :230/:238 faces)
        }
    }
}

impl Ipv4Conf {
    /// snort_config.h:454-:455 `hit_ip_maxlayers(uint8_t curr_ip) const
    /// { return max_ip_layers && (curr_ip >= max_ip_layers); }` — the
    /// "curr_ip is the zero based ip layer" comment :453 rides; eval
    /// order R6: both vars bind BEFORE the && short-circuit.
    #[inline]
    pub fn hit_ip_maxlayers(&self, curr_ip: u8) -> bool {
        let armed = self.max_ip_layers != 0; // :455 LHS (C truthy int)
        let over = curr_ip >= self.max_ip_layers; // :455 RHS
        armed && over
    }

    /// snort_config.h:500-:501 `is_address_anomaly_check_enabled()` —
    /// the :405 gate read.
    #[inline]
    pub fn is_address_anomaly_check_enabled(&self) -> bool {
        self.address_anomaly_check_enabled // :501 `return address_anomaly_check_enabled;`
    }

    /// snort_config.h:777 `SO_PUBLIC bool tunnel_bypass_enabled(uint16_t
    /// proto) const` — OUT-OF-LINE in C (snort_config.cc); the
    /// witness_18f SYNTHETIC mask fold (module doc; the cd_vxlang/cd_
    /// geneve/cd_mpls closure family): mask bit SET -> bypass off.
    #[inline]
    pub fn tunnel_bypass_enabled(&self, proto: u16) -> bool {
        (self.tunnel_mask & proto) == 0 // witness fold, SYNTHETIC (module doc)
    }
}

/// The row-scoped DecodeData SEAM (cd_icmp4.rs:177-:197 Icmp4DecodeData
/// precedent — the real DecodeData owner stays OPEN): THIS TU touches
/// `decode_flags` (:270 |=, :303/:307 |=, :322/:333 read, :328 |=, :331
/// &= ~, :346 read), the IpApi legs (:225/:233 type reads, :243 set,
/// :248-:252 update — the src/dst SfIp faces + the IAT `ip_type` slot)
/// and `set_pkt_type` (:336). The cc:338 MiscTests read side NEVER
/// touches ip_api (the len PARAM carries the option span), so no
/// dgram/payload legs land (LEFT-OPEN, cited where the C reads them in
/// the cite-only world).
#[derive(Clone, Default)]
pub struct Ipv4DecodeData {
    pub decode_flags: u64, // decode_data.h DecodeFlags face
    pub src: SfIp, // :243/:250 ip_api src leg
    pub dst: SfIp, // :243/:251 ip_api dst leg
    pub ip_type: u8, // ip.h:38 IAT face (:225/:233 reads, IAT slots above)
    pub pkt_type: u8, // decode_data.h:192-:195 set/get_pkt_type face
}

/// :53-:58 the pegs[] table + :60-:66 the Stats/THREAD_LOCAL face —
/// CITE-NEVER-LAND body (module doc PEGS head): `const PegInfo pegs[]`
/// = `{ CountType::SUM, "bad_checksum", "nonzero ip checksums" }` :55 +
/// `{ CountType::SUM, "checksum_bypassed", "checksum calculations
/// bypassed" }` :56 + `{ CountType::END, nullptr, nullptr }` :57.
///
/// :69-:93 `static const RuleMap ipv4_rules[]` — TWENTY-ONE data rows +
/// the :92 `{ 0, nullptr }` terminator; sids ALL RESIDENT codec_module.rs
/// (grep census THIS pass: the 21 rule sids + 293/151/150/452/459/449 all
/// exist in enum CodecSid — ZERO new consts), msgs byte-exact off the
/// ground strings. THE table-only row: DECODE_IP4_MIN_TTL :87 (no decode
/// site fires it — the parser side does; the table rides COMPLETE).
pub const IPV4_RULES: [RuleMap; 22] = [
    RuleMap { sid: CodecSid::DECODE_NOT_IPV4_DGRAM as u32, msg: Some("not IPv4 datagram") }, // :71
    RuleMap { sid: CodecSid::DECODE_IPV4_INVALID_HEADER_LEN as u32, msg: Some("IPv4 header length < minimum") }, // :72
    RuleMap { sid: CodecSid::DECODE_IPV4_DGRAM_LT_IPHDR as u32, msg: Some("IPv4 datagram length < header field") }, // :73
    RuleMap { sid: CodecSid::DECODE_IPV4OPT_BADLEN as u32, msg: Some("IPv4 options found with bad lengths") }, // :74
    RuleMap { sid: CodecSid::DECODE_IPV4OPT_TRUNCATED as u32, msg: Some("truncated IPv4 options") }, // :75
    RuleMap { sid: CodecSid::DECODE_IPV4_DGRAM_GT_CAPLEN as u32, msg: Some("IPv4 datagram length > captured length") }, // :76
    RuleMap { sid: CodecSid::DECODE_ZERO_TTL as u32, msg: Some("IPv4 packet with zero TTL") }, // :77
    RuleMap { sid: CodecSid::DECODE_BAD_FRAGBITS as u32, msg: Some("IPv4 packet with bad frag bits (both MF and DF set)") }, // :78
    RuleMap { sid: CodecSid::DECODE_IP4_LEN_OFFSET as u32, msg: Some("IPv4 packet frag offset + length exceed maximum") }, // :79
    RuleMap { sid: CodecSid::DECODE_IP4_SRC_THIS_NET as u32, msg: Some("IPv4 packet from 'current net' source address") }, // :80
    RuleMap { sid: CodecSid::DECODE_IP4_DST_THIS_NET as u32, msg: Some("IPv4 packet to 'current net' dest address") }, // :81
    RuleMap { sid: CodecSid::DECODE_IP4_SRC_MULTICAST as u32, msg: Some("IPv4 packet from multicast source address") }, // :82
    RuleMap { sid: CodecSid::DECODE_IP4_SRC_RESERVED as u32, msg: Some("IPv4 packet from reserved source address") }, // :83
    RuleMap { sid: CodecSid::DECODE_IP4_DST_RESERVED as u32, msg: Some("IPv4 packet to reserved dest address") }, // :84
    RuleMap { sid: CodecSid::DECODE_IP4_SRC_BROADCAST as u32, msg: Some("IPv4 packet from broadcast source address") }, // :85
    RuleMap { sid: CodecSid::DECODE_IP4_DST_BROADCAST as u32, msg: Some("IPv4 packet to broadcast dest address") }, // :86
    RuleMap { sid: CodecSid::DECODE_IP4_MIN_TTL as u32, msg: Some("IPv4 packet below TTL limit") }, // :87
    RuleMap { sid: CodecSid::DECODE_IP4_DF_OFFSET as u32, msg: Some("IPv4 packet both DF and offset set") }, // :88
    RuleMap { sid: CodecSid::DECODE_IP_RESERVED_FRAG_BIT as u32, msg: Some("IPv4 reserved bit set") }, // :89
    RuleMap { sid: CodecSid::DECODE_IP_OPTION_SET as u32, msg: Some("IPv4 option set") }, // :90
    RuleMap { sid: CodecSid::DECODE_IP4_HDR_TRUNC as u32, msg: Some("truncated IPv4 header") }, // :91
    RuleMap { sid: 0, msg: None }, // :92 `{ 0, nullptr }`
];

/// :95-:108 `class Ipv4Module : public BaseCodecModule` — the :98
/// TWO-arg `BaseCodecModule(CD_IPV4_NAME, CD_IPV4_HELP)` ctor face (the
/// HELP slot carries the ADD_DLT splice; contrast the cd_mpls 3-arg
/// params-carrying sibling — NO params table in this TU); get_rules
/// :100-:101 lands below. get_pegs :103-:104 (`return pegs;`) and
/// get_counts :106-:107 (the `reinterpret_cast<PegCount*>(&stats)`) are
/// PEG cite-never-land (module doc PEGS head — no Rust slot lands).
#[derive(Debug)]
pub struct Ipv4Module {
    pub base: BaseCodecModule,
}

impl Ipv4Module {
    /// :98 the ctor face (no config exists — contrast the cd_mpls
    /// MplsCodecConfig face; Ipv4Module carries ONLY the base).
    pub fn new() -> Ipv4Module {
        Ipv4Module {
            base: BaseCodecModule::new(CD_IPV4_NAME, CD_IPV4_HELP), // :98
        }
    }

    /// :100-:101 the get_rules override -> the stored 22-row table.
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &IPV4_RULES // :101 `return ipv4_rules;`
    }
}

impl Default for Ipv4Module {
    fn default() -> Self {
        Self::new()
    }
}

/// :110-:130 `class Ipv4Codec : public Codec` — the :113 `Codec(CD_
/// IPv4_NAME)` ctor face carries NO state; get_data_link_type :115 /
/// get_protocol_ids :116 / decode :117 land REAL; log :118 / encode
/// :119-:120 / update :121-:122 / format :123 are the cite-never-land
/// world (the tail L O G G E R / E N C O D E R comments — ZERO stub-
/// callable fns); the PRIVATE helpers :126-:129 land below
/// (valid_checksum_from_daq static / IP4AddrTests / IPMiscTests /
/// DecodeIPOptions).
#[derive(Debug, Default)]
pub struct Ipv4Codec {}

// ---- the IP4Hdr byte-window overlay (ipv4.h:46-:56 field layout) ----
// ip_verhl@0 :47 / ip_tos@1 :48 / ip_len@2-3 :49 / ip_id@4-5 :50 /
// ip_off@6-7 :51 / ip_ttl@8 :52 / ip_proto@9 :53 / ip_csum@10-11 :54 /
// ip_src@12-15 :55 / ip_dst@16-19 :56 — the sed-pinned layout THIS pass
// (the cd_udp.rs:556-:584 ip4_len/ip4_hlen/ip4_sip/ip4_dip landed twins,
// dup-not-import family; row-scoped names REUSED).

/// ipv4.h:62-:63 `ver() { return (ip_verhl >> 4); }` — the :187 gate.
#[inline]
fn ip4_ver(h: &[u8]) -> u8 {
    *h.first().unwrap_or(&0) >> 4
}

/// ipv4.h:59-:60 `hlen() { return (uint8_t)((ip_verhl & 0x0f) << 2); }`
/// — the :195 store + :197 gate + :340 lyr + the :263 cksum len.
#[inline]
fn ip4_hlen(h: &[u8]) -> u8 {
    (*h.first().unwrap_or(&0) & 0x0f) << 2
}

/// ipv4.h:68-:69 `len() { return ntohs(ip_len); }` — BE bytes 2-3.
#[inline]
fn ip4_len(h: &[u8]) -> u16 {
    u16::from_be_bytes([*h.get(2).unwrap_or(&0), *h.get(3).unwrap_or(&0)])
}

/// ipv4.h:77-:78 `off_w_flags() { return ntohs(ip_off); }` — BE bytes
/// 6-7 (the :288 store; the rb/df/mf/off getters h:80-:90 ride the
/// :294/:300/:306/:310 inline masks below).
#[inline]
fn ip4_off_w_flags(h: &[u8]) -> u16 {
    u16::from_be_bytes([*h.get(6).unwrap_or(&0), *h.get(7).unwrap_or(&0)])
}

/// ipv4.h:53 + :74-:75 `proto() { return ip_proto; }` — byte 9 (raw
/// IpProtocol u8 face; the :350/:353 reads).
#[inline]
fn ip4_proto(h: &[u8]) -> u8 {
    *h.get(9).unwrap_or(&0)
}

/// ipv4.h:55 + :127-:128 `get_src() { return ip_src; }` — the raw
/// uint32 slot, LE-host load of bytes 12-15 (the cd_udp.rs:568-:573
/// twin; the :365/:383 compare faces).
#[inline]
fn ip4_sip(h: &[u8]) -> u32 {
    u32::from_le_bytes([
        *h.get(12).unwrap_or(&0),
        *h.get(13).unwrap_or(&0),
        *h.get(14).unwrap_or(&0),
        *h.get(15).unwrap_or(&0),
    ])
}

/// ipv4.h:56 + :130-:131 `get_dst() { return ip_dst; }` — bytes 16-19
/// (the cd_udp.rs:578-:583 twin).
#[inline]
fn ip4_dip(h: &[u8]) -> u32 {
    u32::from_le_bytes([
        *h.get(16).unwrap_or(&0),
        *h.get(17).unwrap_or(&0),
        *h.get(18).unwrap_or(&0),
        *h.get(19).unwrap_or(&0),
    ])
}

/// The row-scoped codec_event wrapper (the cd_icmp4.rs:1217
/// codec_event_icmp4 house pattern — EVERY event site rides its ground
/// statement slot, never sorted).
#[inline]
fn codec_event_ipv4(codec: &CodecData, sid: u32, sink: QueueSink) {
    crate::framework::codec::codec_event(codec, sid, &mut *sink);
}

impl Ipv4Codec {
    /// :113 `Ipv4Codec() : Codec(CD_IPV4_NAME) { }` — state-free; the
    /// :754-:755 `static Codec* ctor(Module*)` IGNORES the Module
    /// (DRIFT cite vs the cd_mpls :347-:355 config-threading `if (m)`
    /// face — Ipv4Codec owns NO config; Option kept for the ctor shape
    /// and the faceA call-probe compatibility).
    pub fn ctor(_m: Option<&Ipv4Module>) -> Ipv4Codec {
        Ipv4Codec::default() // :755 `new Ipv4Codec` — the arg IGNORED
    }

    /// :150-:153 out-of-line get_data_link_type — EXACTLY ONE emplace,
    /// `v.emplace_back(DLT_IPV4)` :152 (the 228 SYNTHETIC ext#4 face;
    /// contrast the cd_eth 2-push PIN face).
    pub fn get_data_link_type(&self, v: &mut Vec<i32>) {
        v.push(DLT_IPV4); // :152
    }

    /// :155-:159 out-of-line get_protocol_ids — the deterministic
    /// emplace x2 face: ETHERTYPE_IPV4 :157 (2048, protocol_id::
    /// ETHERTYPE_IPV4 RESIDENT framework/codec.rs:159) THEN (ProtocolId)
    /// IPIP :158 (4, protocol_id::IPIP RESIDENT :133 — the C casts the
    /// ProtocolId enumerator, same u16 bits).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ETHERTYPE_IPV4); // :157 (2048)
        v.push(protocol_id::IPIP); // :158 (4, RESIDENT)
    }

    /// :133-:148 out-of-line `static bool valid_checksum_from_daq(const
    /// RawData&)` — VERBATIM statement-for-statement. The
    /// `daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA)` getter
    /// face folds to `Option<Ipv4Pdd>` (None == the nullptr the :137
    /// first arm already models); the :143 pointer difference
    /// `raw.data - data != pdd->l3_offset` folds to the `daq_payload_
    /// delta` param (cd_icmp4.rs:507-:520 DaqFace precedent — probe-
    /// faked pointer math, NEVER ABI). `stats.cksum_bypassed++` :146 is
    /// the PEG cite-never-land face (module doc). R6 eval order: the
    /// :137 four-arm || chain binds its guards in C order.
    pub fn valid_checksum_from_daq(daq: Ipv4DaqFace) -> bool {
        let pdd = match daq.pdd {
            Some(p) => p,
            None => return false, // :137 `if (!pdd ...)` first arm
        };
        // :137 the three remaining || arms, C short-circuit order:
        let ok_cksum = pdd.l3_checksum; // :137
        let ok_ip4 = pdd.ipv4; // :137
        let ok_l3 = pdd.l3; // :137
        if !ok_cksum || !ok_ip4 || !ok_l3 {
            return false; // :138
        }
        // :139 "Sanity check to make sure we're talking about the same
        // thing if offset is available" — the :140 sentinel arm.
        if pdd.l3_offset != DAQ_PKT_DECODE_OFFSET_INVALID {
            // :142-:144 `if (raw.data - data != pdd->l3_offset) return
            // false;` — the payload_delta fold (param doc above).
            if daq.payload_delta != pdd.l3_offset {
                return false; // :144
            }
        }
        // :146 `stats.bad... ` stats.cksum_bypassed++ — PEG cite-never-
        // land (module doc PEGS head; NOTHING lands).
        true // :147
    }

    /// :161-:357 out-of-line decode — statement order VERBATIM, R6 var-
    /// first eval EVERY compound. The config legs ride the Ipv4Conf seam
    /// (cc:173/:230/:238/:405/:260, struct doc); the DAQ legs ride
    /// Ipv4DaqFace; `snort` is the row-scoped DecodeData seam above. The
    /// arg count sits INSIDE the clippy gate (the cd_icmp4 7-arg decode
    /// precedent — NO allowance needed, NO allowance lands).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut Ipv4DecodeData,
        conf: &Ipv4Conf,
        daq: Ipv4DaqFace,
        sink: QueueSink<'_>,
    ) -> bool {
        // :163-:164 `uint32_t ip_len; /* length from the start of the ip
        // hdr to the pkt end */ uint16_t hlen;  /* ip header length */` —
        // the C uninitialized decls become Rust declare-then-assign; the
        // first LIVE writes ride :194/:195 (the :166-:201 gates all
        // return before them in the same path).
        // C decl-site literal (the declare-then-assign face above):
        // every C path reads these only after its own :194/:195 write.
        #[allow(clippy::needless_late_init)] // cited decl-site pin (the
        // statement-verbatim law keeps the C LOCAL decl ABOVE its gates)
        let ip_len: u32;
        #[allow(clippy::needless_late_init)] // the hlen twin (same C
        // decl-site face: :195 assigns inside the hlen gate path)
        let hlen: u16;

        // :166-:171 the short gate: raw.len < IP4_HEADER_LEN (20) ->
        // UNSURE_ENCAP-guarded EV 425 + return false (vectors: the 19-L
        // face NEVER reads the header).
        if raw.len < u32::from(IP4_HEADER_LEN) {
            // :168-:169 `if ((codec.codec_flags & CODEC_UNSURE_ENCAP) ==
            // 0) codec_event(codec, DECODE_IP4_HDR_TRUNC);` — var first.
            let no_uncertain = (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0; // :168 LHS
            if no_uncertain {
                codec_event_ipv4(codec, CodecSid::DECODE_IP4_HDR_TRUNC as u32, &mut *sink); // :169
            }
            return false; // :170
        }

        // :173-:177 the maxlayers gate (the conf->hit_ip_maxlayers read,
        // snort_config.h:454-:455 face folded in Ipv4Conf::hit_ip_maxlayers).
        let hit_max = conf.hit_ip_maxlayers(codec.ip_layer_cnt); // :173 the call
        if hit_max {
            codec_event_ipv4(codec, CodecSid::DECODE_IP_MULTIPLE_ENCAPSULATION as u32, &mut *sink); // :175
            return false; // :176
        }

        // :179 `++codec.ip_layer_cnt;` u8 wrap face kept via wrapping_add.
        codec.ip_layer_cnt = codec.ip_layer_cnt.wrapping_add(1);

        /* :180 "/* lay the IP struct over the raw data */" — the
         * :181 `reinterpret_cast<const ip::IP4Hdr*>(raw.data)` overlay
         * lands as the raw byte window (the gre/icmp4 field-face law). */
        let iph = raw.data; // :181

        /* :183-:186 the DLT_RAW comment rides VERBATIM:
           "with datalink DLT_RAW it's impossible to differ ARP datagrams
            from IP. So we are just ignoring non IP datagrams" */
        // :187-:192 the version gate.
        if ip4_ver(iph) != 4 {
            // :189-:190 the SAME UNSURE_ENCAP-guarded shape (var first).
            let no_uncertain = (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0; // :189 LHS
            if no_uncertain {
                codec_event_ipv4(codec, CodecSid::DECODE_NOT_IPV4_DGRAM as u32, &mut *sink); // :190
            }
            return false; // :191
        }

        ip_len = u32::from(ip4_len(iph)); // :194 `ip_len = iph->len();` (BE ntohs face)
        hlen = u16::from(ip4_hlen(iph)); // :195 `hlen = iph->hlen();` (uint8 -> uint16 widening)

        // :197-:201 the hlen minimum gate (EV 2, NO UNSURE guard).
        if hlen < u16::from(IP4_HEADER_LEN) {
            codec_event_ipv4(codec, CodecSid::DECODE_IPV4_INVALID_HEADER_LEN as u32, &mut *sink); // :199
            return false; // :200
        }

        // :203-:209 the captured-length gate (EV 6) — the FIXIT-L
        // comments :206-:207 ride ("we should decode this layer if
        // possible instead of stopping now / ip6 etc may have similar
        // issues").
        if ip_len > raw.len {
            codec_event_ipv4(codec, CodecSid::DECODE_IPV4_DGRAM_GT_CAPLEN as u32, &mut *sink); // :205
            return false; // :208
        }
        /* :210-:217 THE `#if 0` DEAD BLOCK — cited NEVER landed (the R
         * dead-face census): `else if (ip_len < len)` + "There is no
         * need to alert when (ip_len < len). Libpcap will capture more
         * bytes than are part of the IP payload. These could be
         * Ethernet trailers, ESP trailers, etc." */

        // :219-:223 the datagram-vs-header sanity gate (EV 3).
        if ip_len < u32::from(hlen) {
            codec_event_ipv4(codec, CodecSid::DECODE_IPV4_DGRAM_LT_IPHDR as u32, &mut *sink); // :221
            return false; // :222
        }

        // :225-:240 THE PREVIOUS-layer TUNNEL fork (the ip_api.type seam
        // reads BEFORE the :243 set). THE 4IN6 arm "/* If the previous
        // layer was not IP-in-IP, this is not a 4-in-6 tunnel */" :227:
        if snort.ip_type == IAT_6 {
            // :228-:231 — the CODEC_NON_IP_TUNNEL clear wins over the
            // bypass READ at the else-if (var first, short-circuit kept).
            let non_ip = (codec.codec_flags & CODEC_NON_IP_TUNNEL) != 0; // :228 LHS
            if non_ip {
                codec.codec_flags &= !CODEC_NON_IP_TUNNEL; // :229
            } else {
                let bypass_on = conf.tunnel_bypass_enabled(TUNNEL_4IN6); // :230 (witness fold)
                if bypass_on {
                    codec.tunnel_bypass = true; // :231
                }
            }
        } else if snort.ip_type == IAT_4 {
            // :233-:240 the 4IN4 twin ("not IP-in-IP, ... not a 4-in-4
            // tunnel" :235; the SAME TUNNEL_4IN4 site :238).
            let non_ip = (codec.codec_flags & CODEC_NON_IP_TUNNEL) != 0; // :236 LHS
            if non_ip {
                codec.codec_flags &= !CODEC_NON_IP_TUNNEL; // :237
            } else {
                let bypass_on = conf.tunnel_bypass_enabled(TUNNEL_4IN4); // :238 (witness fold)
                if bypass_on {
                    codec.tunnel_bypass = true; // :239
                }
            }
        }

        // :242-:243 "// set the api now since this layer has been verified
        // as valid / snort.ip_api.set(iph)" — the SfIp::set_raw RESIDENT
        // face (sf_ip.rs:583-:596: the v4-mapped 0xffff prefix + ip8[12..
        // 16] copy = the C SfIp::set(&s_addr, AF_INET)): the raw LE u32
        // round-trip `from_le_bytes(hdr[off..]).to_le_bytes()` re-presents
        // the SAME wire bytes (the task-pinned face).
        let api_src = ip4_sip(iph); // hdr bytes 12-15 (raw get_src face)
        let api_dst = ip4_dip(iph); // hdr bytes 16-19 (raw get_dst face)
        snort.src.set_raw(&api_src.to_le_bytes(), AF_INET); // :243 src leg
        snort.dst.set_raw(&api_dst.to_le_bytes(), AF_INET); // :243 dst leg
        snort.ip_type = IAT_4; // ip.h set(const IP4Hdr*) -> type = IAT_4

        // :244-:253 "/* update to real IP when needed */" — the NAPT meta
        // leg: `daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_NAPT_INFO)`
        // folds to Option<Ipv4NaptFace> (:245); the :246 arm binds BOTH
        // legs before the && (R6).
        let napti = daq.napt; // :245 getter face (Some == non-null napti)
        if let Some(napti) = napti {
            let layer_match = codec.ip_layer_cnt == napti.ip_layer; // :246 RHS
            if layer_match {
                // :248-:249 `SfIp real_src; SfIp real_dst;` — the local
                // pair (default ctor == IpApi SfIp default).
                let mut real_src = SfIp::default(); // :248
                let mut real_dst = SfIp::default(); // :249
                // :250 `real_src.set(&napti->src_addr, daq_napt_info_src_
                // addr_family(napti));` — the raw-u32 feed + the accessor
                // fam face (u16 -> int cast, SYNTHETIC members).
                real_src.set_raw(&napti.src_addr.to_le_bytes(), i16::try_from(napti.src_addr_family).unwrap_or(AF_INET)); // :250
                // :251 the dst twin.
                real_dst.set_raw(&napti.dst_addr.to_le_bytes(), i16::try_from(napti.dst_addr_family).unwrap_or(AF_INET)); // :251
                // :252 `snort.ip_api.update(real_src, real_dst);` — the
                // seam fold: the api src/dst legs RE-POINT to the real
                // pair (ip.h:50 update decl; the type/ip.h slots ride).
                snort.src = real_src; // :252
                snort.dst = real_dst; // :252
            }
        }

        /* :255-:257 "IP Header tests: Land attack, and Loop back test"
         * — the :258 call rides BEFORE the checksum arm (vectors pin the
         * EV-before-dflags order). */
        self.ip4_addr_tests(iph, codec, snort, conf, &mut *sink); // :258

        // :260 THE CHECKSUM GATE: `snort::get_network_policy()->ip_
        // checksums() && !valid_checksum_from_daq(raw)` — the policy face
        // folds to conf.ip_checksums (policy.h:202/:233, struct doc);
        // R6: the gate var binds before the &&, the static call second.
        let cksum_on = conf.ip_checksums; // :260 LHS (policy face)
        if cksum_on && !Self::valid_checksum_from_daq(daq) {
            /* :262 the comment rides: "routers drop packets with bad IP
             * checksums, we don't really need to check them..." */
            // :263 `int16_t csum = checksum::ip_cksum(iph, hlen);` — the
            // RESIDENT 18b landed fold `checksum::ip_cksum(buf, len)`
            // (checksum.rs:421) over the header window; the int16_t
            // signedness folds at the `csum &&` truth read (u16 != 0).
            let csum = ip_cksum(iph, usize::from(hlen)); // :263
            // :264 the cppcheck-suppress comment rides ("checksum result
            // depends on packet contents"); the :265 && keeps C order.
            let cooked = codec.is_cooked(); // :265 RHS leg (CODEC_STREAM_REBUILT face)
            if csum != 0 && !cooked {
                // :267-:271 the UNSURE-guarded inner block — var first.
                let no_uncertain = (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0; // :267
                if no_uncertain {
                    // :269 `stats.bad_cksum++;` — PEG cite-never-land
                    // (module doc PEGS head; NOTHING lands).
                    snort.decode_flags |= DECODE_ERR_CKSUM_IP; // :270
                }
                return false; // :272 — EVEN WHEN the guard skipped the
                              // flag write (the vectors' no-flag return
                              // face; the return sits OUTSIDE the :267 if).
            }
        }

        // :276 "/* test for IP options */" + the :277 clear — the RESIDENT
        // CODEC_IPOPT_FLAGS trio-splice (framework/codec.rs:59-:60).
        codec.codec_flags &= !CODEC_IPOPT_FLAGS; // :277

        // :278 `uint8_t ip_opt_len = (uint8_t)(hlen - IP4_HEADER_LEN);`
        // — the widening-trunc cast face (hlen >= 20 gated at :197 so the
        // difference never wraps).
        let mut ip_opt_len: u8 = (hlen - u16::from(IP4_HEADER_LEN)) as u8; // :278

        // :279-:281 the options decode call — start = raw.data + 20 (the
        // pointer feed folds to the window + opt_start BELOW).
        if ip_opt_len > 0 {
            self.decode_ip_options(raw.data, usize::from(IP4_HEADER_LEN), &mut ip_opt_len, codec, &mut *sink); // :281
        }

        // :283-:284 `/* set the remaining packet length */ const_cast<
        // uint8_t&>(raw.len)...` — THE `const_cast<uint32_t&>(raw.len) =
        // ip_len;` MUTATION FACE: the Rust mirror folds to a LOCAL COPY
        // (honest record: the probe NEVER re-reads raw.len after decode,
        // the caller's RawData stays UNMUTATED — the C mutation rides
        // harness-side; Rust NEVER mutates the caller's input).
        let mut raw_local = *raw; // :284 the copy face
        raw_local.len = ip_len; // :284 the mutation lands ON the copy

        // :285 `ip_len -= hlen;` — wrapping kept (ip_len >= hlen per the
        // :219 gate).
        let ip_len = ip_len.wrapping_sub(u32::from(hlen)); // :285 (the shadows C reuse)
        let _ = &raw_local; // the copy's face slot (NEVER re-read — pin above)

        // :287 "/* check for fragmented packets */" + :288.
        let mut frag_off = ip4_off_w_flags(iph); // :288 `iph->off_w_flags()`

        /* :290-:293 the comment rides: "get the values of the reserved,
         * more fragments and don't fragment flags" */
        // :294-:298 the RB arm (EV 448) — the DEAD line :297 `//
        // data.decode_flags |= DECODE_RF;  -- flag never needed` rides
        // cited (the never-land face).
        if frag_off & 0x8000 != 0 {
            codec_event_ipv4(codec, CodecSid::DECODE_IP_RESERVED_FRAG_BIT as u32, &mut *sink); // :296
        }

        // :300-:304 the DF arm — a DOUBLE write (codec flag + dflag).
        if frag_off & 0x4000 != 0 {
            codec.codec_flags |= CODEC_DF; // :302 (RESIDENT 0x0001)
            snort.decode_flags |= DECODE_DF; // :303
        }

        // :306-:307 the MF arm (dflags ONLY).
        if frag_off & 0x2000 != 0 {
            snort.decode_flags |= DECODE_MF; // :307
        }

        // :309-:310 "/* mask off the high bits in the fragment offset
        // field */" — the ipv4.h:90 off() 0x1FFF face.
        frag_off &= 0x1FFF; // :310

        // :312-:320: the DF-AND-offset EV + the LEN_OFFSET arithmetic
        // gate. `(frag_off << 3) + ip_len > IP_MAXPACKET` :318: frag_off
        // u16 promotes to int, <<3 fits (0x1FFF<<3 = 0xFFFF8), then the
        // uint32 ip_len WIDENS the whole compare to unsigned (C promo
        // face mirrored via u32 casts + wrapping add).
        if frag_off != 0 {
            let df_set = (codec.codec_flags & CODEC_DF) != 0; // :314 LHS
            if df_set {
                codec_event_ipv4(codec, CodecSid::DECODE_IP4_DF_OFFSET as u32, &mut *sink); // :315
            }
            // :317 the "we need to multiply by 8" comment rides.
            if (u32::from(frag_off) << 3).wrapping_add(ip_len) > IP_MAXPACKET {
                codec_event_ipv4(codec, CodecSid::DECODE_IP4_LEN_OFFSET as u32, &mut *sink); // :319
            }
        }

        // :322-:331 the FRAG fork — `frag_off || (snort.decode_flags &
        // DECODE_MF)` (var first; the :324 FIXIT-L "identical to
        // DEFRAG_ANOMALY_ZERO" comment rides).
        let frag_leg = frag_off != 0 || (snort.decode_flags & DECODE_MF) != 0; // :322
        if frag_leg {
            if ip_len == 0 {
                codec_event_ipv4(codec, CodecSid::DECODE_ZERO_LENGTH_FRAG as u32, &mut *sink); // :326
            }
            snort.decode_flags |= DECODE_FRAG; // :328
        } else {
            snort.decode_flags &= !DECODE_FRAG; // :331 (the C `&= ~DECODE_FRAG`)
        }

        // :333-:334 the MF-x-DF BOTH-SET anomaly (EV 405) — the codec-
        // side CODEC_DF leg (NOT the dflag DECODE_DF) is the gate twin,
        // both vars bind first.
        let mf_leg = (snort.decode_flags & DECODE_MF) != 0; // :333 LHS
        let df_leg = (codec.codec_flags & CODEC_DF) != 0; // :333 RHS
        if mf_leg && df_leg {
            codec_event_ipv4(codec, CodecSid::DECODE_BAD_FRAGBITS as u32, &mut *sink); // :334
        }

        snort.pkt_type = PKT_TYPE__IP; // :336 `snort.set_pkt_type(PktType::IP)` (h:192-:193 face)
        // :337 the RESIDENT PROTO_BIT__IP ride (decode_data.h:87 0x000001
        // == crate::detection::rtn_checks:25 — REUSE-NEVER-REDECLARE, the
        // cd_mpls :53-:56 rule re-grepped THIS pass).
        codec.proto_bits |= crate::detection::rtn_checks::PROTO_BIT__IP; // :337
        self.ip_misc_tests(iph, codec, u16::from(IP4_HEADER_LEN) + u16::from(ip_opt_len), &mut *sink); // :338

        // :340 `codec.lyr_len = hlen - codec.invalid_bytes;` — u16
        // wrapping face (DecodeIPOptions only shrinks o_len, invalid
        // lands <= its slice; the C u16 promo keeps mod-2^16).
        codec.lyr_len = hlen.wrapping_sub(codec.invalid_bytes); // :340
        // :341-:342 the CLEAR pair — the C comment rides: "necessary
        // since next protos numbers share same space for both ip4 and ip6".
        codec.curr_ip6_extension = 0; // :341
        codec.ip6_extension_count = 0; // :342

        /* :344-:348 the gate comment + the DEAD FIXIT-M comment ride:
         * "if this packet isn't a fragment / or if it is, its a UDP
         *  packet and offset is 0" — the commented-out `((frag_off == 0)
         *  && (iph->proto() == IpProtocol::UDP))` arm is NEVER-land
         *  ("FIXIT-M this forces flow to udp instead of ip" :347). */
        // :346 the DECODE_FRAG read (var first).
        let fragged = (snort.decode_flags & DECODE_FRAG) != 0; // :346
        if !fragged {
            // :350 `to_utype(iph->proto()) >= to_utype(MIN_UNASSIGNED_IP_
            // PROTO)` — the MIN const RESIDENT framework/codec.rs:119
            // (143; ip_protocol::MIN_UNASSIGNED_IP_PROTO, REUSE-NEVER-
            // REDECLARE); the to_utype widening (u16) mirrored on both
            // legs (the cd_udp landed gate posture).
            let proto: ProtocolId = ip4_proto(iph).into(); // :350 to_utype leg (u8 -> u16)
            let unassigned = proto >= u16::from(ip_protocol::MIN_UNASSIGNED_IP_PROTO); // :350
            if unassigned {
                codec_event_ipv4(codec, CodecSid::DECODE_IP_UNASSIGNED_PROTO as u32, &mut *sink); // :351
            }
            codec.next_prot_id = ip4_proto(iph).into(); // :353 `(ProtocolId)iph->proto()` (the C u8 -> u16 cast)
        }

        true // :356
    }

    /// :359-:413 out-of-line `IP4AddrTests(const ip::IP4Hdr*, const
    /// CodecData&, const DecodeData&)` — the Land/loopback addr suite.
    /// The DecodeData operand feeds ONLY the :407/:410 `snort.ip_api.
    /// get_src()/get_dst()` sfvar legs (the WITNESS FOLD: Multicast-
    /// ReservedIp nullptr -> sfvar_ip_in FALSE, module doc — the seam's
    /// src/dst SfIp legs ride as the never-read witness operands at the
    /// fold sites). The conf leg (C reads `codec.conf`) rides the
    /// Ipv4Conf seam. RAW u32 compares ride the ip4_sip/ip4_dip LE
    /// faces (the wire-order s_addr == the C field value on an LE host).
    fn ip4_addr_tests(
        &self,
        iph: &[u8],
        codec: &CodecData,
        snort: &Ipv4DecodeData,
        conf: &Ipv4Conf,
        sink: QueueSink,
    ) {
        let ip_src = ip4_sip(iph); // :365 raw ip_src side-read
        let ip_dst = ip4_dip(iph); // :365 raw ip_dst side-read

        // :364-:368 "check all 32 bits ..." the Land attack (EV 151).
        if ip_src == ip_dst {
            codec_event_ipv4(codec, CodecSid::DECODE_BAD_TRAFFIC_SAME_SRCDST as u32, &mut *sink); // :367
        }

        // :370-:372 ipv4.h:103-:104 `is_src_broadcast() { return ip_src
        // == IP4_BROADCAST; }` (EV 413).
        if ip_src == IP4_BROADCAST {
            codec_event_ipv4(codec, CodecSid::DECODE_IP4_SRC_BROADCAST as u32, &mut *sink); // :372
        }

        // :374-:375 the is_dst_broadcast twin (ipv4.h:106-:107, EV 414).
        if ip_dst == IP4_BROADCAST {
            codec_event_ipv4(codec, CodecSid::DECODE_IP4_DST_BROADCAST as u32, &mut *sink); // :375
        }

        /* :377-:378 the comment rides VERBATIM:
           "Loopback traffic  - don't use htonl for speed reasons -
            s_addr is always in network order" */
        // :379-:385 THE WORDS_BIGENDIAN fork: the BE arms
        // `msb_src = (uint8_t)(iph->ip_src >> 24)` :380 /
        // `msb_dst = (uint8_t)(iph->ip_dst >> 24)` :381 are CITED NEVER
        // LANDED (host LE, x86 build); the #else LE arms :383-:384 LAND
        // (probe-pinned):
        let mut msb_src = (ip_src & 0xff) as u8; // :383 LE arm
        let mut msb_dst = (ip_dst & 0xff) as u8; // :384 LE arm

        // :386-:390 "check the msb ..." the loopback pair (EV 150) — the
        // || binds both legs first (R6).
        let src_loop = msb_src == IP4_LOOPBACK; // :387 LHS
        let dst_loop = msb_dst == IP4_LOOPBACK; // :387 RHS
        if src_loop || dst_loop {
            codec_event_ipv4(codec, CodecSid::DECODE_BAD_TRAFFIC_LOOPBACK as u32, &mut *sink); // :389
        }

        // :391-:393 the this-net src arm (EV 408).
        if msb_src == IP4_THIS_NET {
            codec_event_ipv4(codec, CodecSid::DECODE_IP4_SRC_THIS_NET as u32, &mut *sink); // :393
        }

        // :395-:396 the this-net dst arm (EV 409).
        if msb_dst == IP4_THIS_NET {
            codec_event_ipv4(codec, CodecSid::DECODE_IP4_DST_THIS_NET as u32, &mut *sink); // :396
        }

        // :398-:400 "check the 'msn' (most significant nibble) ..." —
        // the C uint8_t >>= promotes to int, truncs back (same value).
        msb_src >>= 4; // :399 (0x7F msn = 7 NEVER matches 0x0E/0x0F —
        msb_dst >>= 4; // :400  the loopback/msn disjointness rides vectors)

        // :402-:403 the multicast msn arm (EV 410).
        if msb_src == IP4_MULTICAST {
            codec_event_ipv4(codec, CodecSid::DECODE_IP4_SRC_MULTICAST as u32, &mut *sink); // :403
        }

        // :405-:412 THE ANOMALY-GATED RESERVED pair (the :405 gate =
        // snort_config.h:500-:501 face): EACH :407/:410 || is
        // `msb == IP4_RESERVED || sfvar_ip_in(MulticastReservedIp,
        // snort.ip_api.get_src())` — THE WITNESS FOLD:
        // `sfvar_in = false` at the harness face (witness_ipvars.cc:
        // sfip_var_from_string -> nullptr, NDEBUG skips the cc:732
        // asserts; the snort.src/snort.dst SfIp legs stand as the never-
        // read witness operands). The `msb == IP4_RESERVED` arm stays
        // REAL; both legs bind before the || (R6).
        let anomaly = conf.is_address_anomaly_check_enabled(); // :405
        if anomaly {
            let sfvar_src_in = false; // witness_ipvars.cc FALSE face (doc)
            let reserved_src = msb_src == IP4_RESERVED; // :407 LHS
            if reserved_src || sfvar_src_in {
                codec_event_ipv4(codec, CodecSid::DECODE_IP4_SRC_RESERVED as u32, &mut *sink); // :408
            }
            let sfvar_dst_in = false; // witness_ipvars.cc FALSE face (doc)
            let reserved_dst = msb_dst == IP4_RESERVED; // :410 LHS
            if reserved_dst || sfvar_dst_in {
                codec_event_ipv4(codec, CodecSid::DECODE_IP4_DST_RESERVED as u32, &mut *sink); // :411
            }
        }
        let _ = &snort.src; // the witness operand pin (NEVER read — fold above)
        let _ = &snort.dst; // the witness operand pin (NEVER read — fold above)
    }

    /// :416-:484 out-of-line `IPMiscTests(const ip::IP4Hdr* const ip4h,
    /// const CodecData& codec, uint16_t len)` — "/* IPv4-layer decoder
    /// rules */" :415; the IpOptionIterator range-for over the option
    /// region. THE ITER FACE (ipv4_options.cc:61-:70, sed-pinned):
    /// ctor(ip4h, uint8_t valid_hdr_len) -> start_ptr = hdr + 20;
    /// `valid_hdr_len < IP4_HEADER_LEN` -> end_ptr = start; else
    /// end_ptr = hdr + valid_hdr_len. THE DECIMAL-NARROW FACE: the ctor
    /// arg is `uint8_t` — the :423 call CASTS `(uint8_t)(len)` BEFORE
    /// the ctor sees it (the task-pinned semantics); the :278 ip_opt_len
    /// is u8 and the :338 sum <= 255 by hlen <= 60, so no observable
    /// trunc at the harness face — the cast lands VERBATIM below. Range-
    /// for = `while ptr != end` (h:96-:99 operator!=, ptr EQUALITY only
    /// — an overshoot would free-run in C; well-formed windows end the
    /// walk). ++ = the GCC-branch next() face (h:66-:72 — the
    /// __GNUC__/gcc branch of the h:63-:85 fork LANDS, x86 gcc build):
    /// `tmp_len = ((uint8_t)code <= 1) ? 1 : len;` advance by tmp_len —
    /// YES even when len < 2 on the gcc branch (the #else legible leg
    /// NEVER compiles here, cited NEVER landed). switch `break` exits the
    /// SWITCH (the loop still advances — the C face), `continue` skips to
    /// the SAME advance: semantically identical increments (the honest
    /// CITE at the arms). len/data reads ride `.get().unwrap_or(&0)`
    /// (the cd_icmp4 byte-window posture; C reads the packet bytes past
    /// the header window — the OOB-0 fold at the capture tail, cited).
    fn ip_misc_tests(&self, iph: &[u8], codec: &CodecData, len: u16, sink: QueueSink) {
        /* :418 "/* Yes, it's an ICMP-related vuln in IP options. */" */
        let mut cnt: i32 = 0; // :419 `int cnt = 0;` (C signed)

        /* :421-:422 the comment rides: "Alert on IP packets with either
         * 0x07 (Record Route) or 0x44 (Timestamp) options that are
         * specially crafted." */
        // :423 `ip::IpOptionIterator iter(ip4h, (uint8_t)(len));` — the
        // u16 -> uint8_t cast lands FIRST (ctor cc semantics above).
        let valid_hdr_len = (len as u8) as usize; // :423 the (uint8_t) cast face
        let start = usize::from(IP4_HEADER_LEN); // opts.h:64 `start_ptr = hdr + IP4_HEADER_LEN`
        let end = if valid_hdr_len < usize::from(IP4_HEADER_LEN) {
            start // opts.h:67 end_ptr = start (the < 20 leg lands degenerate)
        } else {
            valid_hdr_len // opts.h:69 `end_ptr = hdr + valid_hdr_len`
        };

        // :424-:480 THE range-for body; :426 `++cnt` FIRST (every visited
        // option counts). THE C switch-`break` and `continue` BOTH land
        // on the loop increment (the IpOptions cursor step) — THE RUST
        // FIDELITY FACE: a bare Rust `break` would hit the WHILE and a
        // bare `continue` would SKIP the increment, so the switch body
        // rides a labeled block `break 'opt_switch` — both C landings
        // land at the SAME shared advance below (cited restructure; the
        // decode_ip_options goto/default_case face's twin posture).
        let mut ptr = start; // the begin() cursor (opts.cc:74-:76)
        while ptr != end {
            cnt += 1; // :426

            let code = *iph.get(ptr).unwrap_or(&0); // opt.code (h:50, window overlay)
            let opt_len = *iph.get(ptr + 1).unwrap_or(&0); // opt.len (h:51)

            'opt_switch: {
                match code {
                    IPOPT_EOL => {
                        // :430-:432 EOL: `--cnt; break;` — break exits the
                        // SWITCH (the advance below runs — C face).
                        cnt -= 1; // :431
                    }
                    IPOPT_RR => {
                        // :434-:452 THE RR arm: :436 `const uint8_t length =
                        // opt.len;` (the RAW len byte — NOT get_len).
                        let length = opt_len; // :436
                        if length < 3 {
                            break 'opt_switch; // :437-:438 C `continue` -> the advance (doc above)
                        }
                        let pointer = *iph.get(ptr + 2).unwrap_or(&0); // :440 `uint8_t pointer = opt.data[0]`
                        // :442-:445 "If the pointer goes past the end of the
                        // data, then the data is full. That's okay."
                        if pointer >= length {
                            break 'opt_switch; // :444-:445 C `continue` -> the advance
                        }
                        // :446-:449 "If the remaining space in the option
                        // isn't a multiple of 4 bytes, alert." — the C uint8
                        // -> int promotions: ((length + 1) - pointer) % 4 on
                        // INTS (pointer < length so unsigned-safe; % > 0).
                        let expr = (i32::from(length) + 1) - i32::from(pointer); // :448 int-promoted
                        if expr % 4 != 0 {
                            codec_event_ipv4(codec, CodecSid::DECODE_ICMP_DOS_ATTEMPT as u32, &mut *sink); // :449 (EV 452)
                        }
                        break 'opt_switch; // :451 C `break` — exits the switch (the advance runs)
                    }
                    IPOPT_TS => {
                        // :453-:476 THE TS arm: :455 `const uint8_t length =
                        // opt.get_len();` — h:57-:58 `get_len() { return
                        // ((uint8_t)code <= 1) ? 1 : len; }` (code 0x44 > 1
                        // so len; the face kept EXPLICIT via the ternary).
                        let length = if code <= 1 { 1 } else { opt_len }; // :455 (h:57-:58)
                        if length < 2 {
                            break 'opt_switch; // :456-:457 C `continue` -> the advance
                        }
                        let pointer = *iph.get(ptr + 2).unwrap_or(&0); // :459 opt.data[0]
                        // :461-:464 the SAME "data is full" comment pair.
                        if pointer >= length {
                            break 'opt_switch; // :463-:464 C `continue` -> the advance
                        }
                        // :465-:468 the multiple-of-4 leg (int promo twin).
                        let expr4 = (i32::from(length) + 1) - i32::from(pointer); // :467
                        if expr4 % 4 != 0 {
                            codec_event_ipv4(codec, CodecSid::DECODE_ICMP_DOS_ATTEMPT as u32, &mut *sink); // :468
                        }
                        // :469-:473 "If there is a timestamp + address, we
                        // need a multiple of 8 bytes instead" — the
                        // `(opt.data[1] & 0x01) && /* address flag */` leg
                        // binds FIRST (&&), then the ((length+1)-pointer)%8
                        // leg (var first, R6):
                        let addr_flag = (*iph.get(ptr + 3).unwrap_or(&0) & 0x01) != 0; // :471
                        let m8 = {
                            let expr8 = (i32::from(length) + 1) - i32::from(pointer); // :472
                            expr8 % 8 != 0
                        };
                        if addr_flag && m8 {
                            codec_event_ipv4(codec, CodecSid::DECODE_ICMP_DOS_ATTEMPT as u32, &mut *sink); // :473
                        }
                        break 'opt_switch; // :475 C `break` — exits the switch
                    }
                    // :477-:478 `default: break;` — NOP/SECURITY/LSRR/.../
                    // RTRALT ride HERE in MiscTests (RTRALT is NOT a label —
                    // the MiscTests switch reads ONLY EOL/RR/TS).
                    _ => {
                        // :478 break (exits the switch — the advance runs)
                    }
                }
            }

            // :424 loop-increment == IpOptionIteratorIter::operator++
            // (h:104-:108 `opt = &opt->next()`) == the GCC next() face
            // (h:66-:72): tmp_len u8 face, code <= 1 -> 1 ELSE len.
            let tmp_len = if code <= 1 { 1 } else { opt_len }; // h:68
            ptr += usize::from(tmp_len); // h:69-:70 (u8 -> pointer diff widening)
        }

        // :482-:483 the leftover-option gate (EV 444) — cnt > 0 AFTER the
        // walk (the EOL --cnt un-count).
        if cnt > 0 {
            codec_event_ipv4(codec, CodecSid::DECODE_IP_OPTION_SET as u32, sink); // :483
        }
    }

    /// :486-:553 out-of-line `DecodeIPOptions(const uint8_t* start,
    /// uint8_t& o_len, CodecData& codec)` — THE option-length validator.
    /// The C `(raw.data + IP4_HEADER_LEN)` pointer feed (:281) folds to
    /// (window, opt_start); `uint8_t& o_len` folds to `&mut u8` (the
    /// shrinks feed :340 invalid_bytes + the :338 MiscTests arg). THE
    /// walk face: `option = &option->next()` :551 == the SAME GCC h:66-
    /// :72 tmp_len step (code <= 1 -> 1 ELSE len — YES even when len < 2,
    /// the same citation as ip_misc_tests). THE `goto default_case` :511
    /// + the RR `// fall through` :515 land AS the shared `did_default`
    ///   block (CITED restructure — the RTRALT flag leg then the default
    ///   body; the RR flag leg then the default body). The negative
    ///   `code` PERSISTENCE (:489, declared OUTSIDE the while): the
    ///   chain only ever assigns negative values and every negative
    ///   IMMEDIATELY returns (:535-:546), so the cross-iteration
    ///   persistence is INERT — the decl shape stays ABOVE the loop (the
    ///   honest inert pin).
    ///   Window reads ride `.get().unwrap_or(&0)` (the capture-tail
    ///   OOB-0 fold, same cite posture — C walks the packet bytes).
    // the did_default late-init: C decl-site literal (the `bool
    // did_default` decl ABOVE the switch, assigns inside the arms).
    #[allow(clippy::needless_late_init)] // cited decl-site pin
    fn decode_ip_options(
        &self,
        hdr: &[u8],
        opt_start: usize,
        o_len: &mut u8,
        codec: &mut CodecData,
        sink: QueueSink,
    ) {
        let mut tot_len: u32 = 0; // :488
        let mut code: i32 = 0; // :489 (`int code = 0;  /* negative error
                               // codes are returned from bad options */`)
                               // — the inert-persistence decl shape rides
                               // OUTSIDE the loop (doc above).

        // :491 `const ip::IpOptions* option = (const ip::IpOptions*)start;`
        // — the cursor folds to an absolute window offset.
        let mut ptr = opt_start; // the :491/:551 cursor face

        // :493 `while (tot_len < o_len)` — u32 vs uint8_t (int -> uint32
        // promotion face: both widened, >= comparisons safe).
        while tot_len < u32::from(*o_len) {
            let opt_code = *hdr.get(ptr).unwrap_or(&0); // option->code (h:50)
            let opt_len = *hdr.get(ptr + 1).unwrap_or(&0); // option->len (h:51)
            let did_default: bool;

            // :495 `switch (option->code)` — u8 discriminator vs the
            // uint8_t enum face (h:33).
            match opt_code {
                IPOPT_EOL => {
                    // :497-:502 EOL: "/* if we hit an EOL, we're done */"
                    tot_len += 1; // :499
                    // :500 `codec.invalid_bytes = o_len - tot_len;` —
                    // uint8->int -> uint32 promo (tot_len <= o_len per
                    // the loop test — NO wrap) -> the u16 field NARROW.
                    codec.invalid_bytes = (u32::from(*o_len) - tot_len) as u16; // :500
                    *o_len = tot_len as u8; // :501 (`o_len = tot_len;` u32->u8 narrow)
                    return; // :502
                    // :503 the vestigial `// fall through` comment rides
                    // CITED (the :499-:502 return makes it DEAD).
                }
                IPOPT_NOP => {
                    // :505-:507 NOP: `tot_len++; break;` (the :503 fall-
                    // through comment above is dead — EOL returns).
                    tot_len += 1; // :506
                    did_default = false;
                }
                IPOPT_RTRALT => {
                    // :509-:511 RTRALT: flag THEN `goto default_case` :511
                    // → the shared block below (CITED restructure).
                    codec.codec_flags |= CODEC_IPOPT_RTRALT_SEEN; // :510
                    did_default = true;
                }
                IPOPT_RR => {
                    // :513-:515 RR: flag THEN the `// fall through` :515
                    // → the SAME shared block (the C label-stack twin).
                    codec.codec_flags |= CODEC_IPOPT_RR_SEEN; // :514
                    did_default = true;
                }
                // :517-:518 `default_case: default:` — EVERY other code
                // enters the block directly.
                _ => {
                    did_default = true;
                }
            }

            if did_default {
                // :520-:533 the chain — EACH leg binds its var first (R6);
                // :520 `if ((tot_len + 1) >= o_len)` (uint32 vs widened
                // uint8):
                if (tot_len + 1) >= u32::from(*o_len) {
                    code = OPT_TRUNC; // :521
                }
                // :523 "/* RFC says that we MUST have at least this much
                // data */" + :524-:525 (`option->len < 2`):
                else if opt_len < 2 {
                    code = OPT_BADLEN; // :525
                }
                // :527 `else if (tot_len + option->get_len() > o_len)` —
                // the default block is reached ONLY with code > 1 (0/1
                // ride the EOL/NOP cases FIRST), so get_len() == len
                // (h:57-:58 face kept explicit); :528 "/* not enough data
                // to read in a perfect world */":
                else if tot_len + u32::from(if opt_code <= 1 { 1 } else { opt_len }) > u32::from(*o_len) {
                    code = OPT_TRUNC; // :529
                }
                // :531-:533 `else if (option->len == 3)` — "/* for IGMP
                // alert */":
                else if opt_len == 3 {
                    codec.codec_flags |= CODEC_IPOPT_LEN_THREE; // :533 (the ONLY non-negative outcome)
                }

                // :535-:546 THE NEGATIVE-EXIT block (:537 "/* Yes, we use
                // TCP_OPT_* for the IP option decoder. */").
                if code < 0 {
                    if code == OPT_BADLEN {
                        codec_event_ipv4(codec, CodecSid::DECODE_IPV4OPT_BADLEN as u32, &mut *sink); // :539 (EV 4)
                    } else if code == OPT_TRUNC {
                        codec_event_ipv4(codec, CodecSid::DECODE_IPV4OPT_TRUNCATED as u32, &mut *sink); // :541 (EV 5)
                    }
                    // :543-:545 the SAME narrow/cast pair as the EOL arm
                    // (the loop test keeps o_len >= tot_len > — NO wrap).
                    codec.invalid_bytes = (u32::from(*o_len) - tot_len) as u16; // :543
                    *o_len = tot_len as u8; // :544
                    return; // :545
                }

                // :548 `tot_len += option->len;` (uint8 -> uint32 widening).
                tot_len += u32::from(opt_len);
            }

            // :551 `option = &(option->next());` — the GCC h:66-:72 step
            // face (the ip_misc_tests citation).
            let tmp_len = if opt_code <= 1 { 1 } else { opt_len }; // h:68
            ptr += usize::from(tmp_len); // h:69-:70
        }
    }
}

// :555-:557 the "L O G G E R" banner rides.
// ==================================================================
// :559-:624 out-of-line log — CITE-NEVER-LAND (the ip-family log/encode
// world; ZERO stub-callable fn lands). The body transcribed BY READING,
// every move cited (the TextLog_Print seam precedent):
//   :561 the `IP4Hdr*` overlay onto raw_pkt; :563-:567 the FIXIT-RC
//   "this does NOT obfuscate correctly" comment + the
//   `SnortConfig::get_conf()->obfuscate()` arm printing
//   "xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx" :566; the ELSE arm :568-:581:
//   in_addr pair from get_src/get_dst :571-:572, the INET_ADDRSTRLEN
//   buffers :574-:575, inet_ntop x2 :577-:578, TextLog_Print "%s -> %s"
//   :580; :583-:584 TextLog_NewLine + TextLog_Putc('\t'); :586-:589 the
//   hlen/len/frag_off consts + `bool mf_set = false`; :591-:593 the
//   "Next:0x%02X TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u" print (the
//   id() NOTH ntohs face :593 = ntohs(ip_id), the cd_tcp RAW face does
//   NOT ride here); :595-:597 "/* print the reserved bit if it's set */"
//   " RB"; :599-:601 " DF"; :603-:607 " MF" + mf_set = true; :609-:615
//   the has_options arm (Tab/NewLine + LogIpOptions(text_log, ip4h,
//   lyr_len) :614 — the SEPARATE log_utils donor, CITE-NEVER-LAND);
//   :617-:623 the mf_set/(frag_off & 0x1FFF) Frag line:
//   "Frag Offset: 0x%04X   Frag Size: 0x%04X\n" with (frag_off &
//   0x1FFF) * 8 :622 and (len - hlen) :622.
//
// :626-:628 the "E N C O D E R" banner rides (x2: :626-:628 + :637-:639).
// :630 `static THREAD_LOCAL std::mt19937* thread_rand = nullptr` +
// :632-:635 `static inline uint16_t IpId_Next() { return (*thread_rand)
// () % UINT16_MAX; }` — the mt19937 encode era, CITE-NEVER-LAND (the
// tinit/tterm arms create/destroy the engine; :159 UINT16_MAX==65535 is
// ALREADY pinning the IP_MAXPACKET value but rides its UINT16_MAX cite).
// :640-:681 out-of-line encode — CITE-NEVER-LAND: :643-:644 the
// `buf.allocate(IP4_HEADER_LEN)` short-false; :646-:647 the in/out
// overlays (the hardcoded 20-byte comment :649); the :650-:656 field
// WRITES in C order (ip_verhl = 0x45 / ip_off = 0 / ip_id = IpId_Next()
// / ip_tos / ip_proto / `ip_len = htons((uint16_t)buf.size())` / ip_csum
// = 0); :658-:669 the enc.forward() src/dst/direct vs swap arms (ip_ttl
// = enc.get_ttl(...) BOTH arms :662/:668); :671-:672 the
// enc.next_proto_set() overwrite by ip4h_out->ip_proto = enc.next_proto;
// :674-:676 the "we save some cycles and use the literal header size"
// comment + `ip_csum = checksum::ip_cksum(ip4h_out, IP4_HEADER_LEN)`
// :676; :678-:679 `enc.next_proto = IpProtocol::IPIP` (4; RESIDENT
// ip_protocol::IPIP framework/codec.rs:100) +
// `enc.next_ethertype = ProtocolId::ETHERTYPE_IPV4` (RESIDENT :159);
// :680 return true.
// :683-:697 out-of-line update — CITE-NEVER-LAND: the IpApi operand
// UNNAMED (never-read); :686-:687 the overlay + hlen; :689-:690
// `updated_len += hlen; h->set_ip_len((uint16_t)updated_len)` (the
// set_ip_len h: writer face = htons into ip_len); :692-:696 the
// `!(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG)` recompute arm
// (ip_csum = 0; ip_csum = checksum::ip_cksum(h, hlen) :694-:695).
// :699-:712 out-of-line format — CITE-NEVER-LAND: :701 the overlay;
// :703-:708 the reverse arm's tmp_ip src/dst SWAP; :710
// `snort.ip_api.set(ip4h)` (the ip_type = IAT_4 face rides — the format
// path never decodes); :711 `snort.set_pkt_type(PktType::IP)`. The
// reverse/UPD_COOKED/UPD_REBUILT_FRAG consts live with the landed
// encode rows (cd_udp.rs imports them) — cited, NEVER re-declared.
// ==================================================================
// :714-:716 the "api" separator banner rides.
// :718-:719 `static Module* mod_ctor() { return new Ipv4Module; }` +
// :721-:722 `static void mod_dtor(Module* m) { delete m; }` — the mod
// pair SET (faceA `ipv4 mod_ctor=1 mod_dtor=1`); the Rust mod face is
// Ipv4Module::new (the stack-owned drop, 18d posture).
// :724-:733 `static void ipv4_codec_ginit()` — the pinit slot SET; the
// :726 "// Reserved addresses within multicast address space (See RFC
// 5771)" comment + THE multicast-reserved STRING LIST (the sfip_var_
// from_string argument, :727-:730 VERBATIM, cite-never-land per the
// witness_ipvars.cc nullptr face above):
//   "[224.1.0.0/16,224.5.0.0/16,224.6.0.0/15,224.8.0.0/13,224.16.0.0/12,
//    224.32.0.0/11,224.64.0.0/10,224.128.0.0/9,225.0.0.0/8,226.0.0.0/7,
//    228.0.0.0/6,234.0.0.0/7,236.0.0.0/7,238.0.0.0/8]"  + "ipv4" tag
// :731; the :732 `assert(MulticastReservedIp)` is the NDEBUG elide face.
// :735-:741 gterm — the pterm slot SET: `if (MulticastReservedIp)
// sfvar_free(MulticastReservedIp);` :737-:738 + the :740 nullptr reset
// (cite-never-land).
// :743-:746 tinit — the tinit slot SET (faceA THE t-arm PIN, tinit=1):
// `thread_rand = new std::mt19937(SnortConfig::static_hash() ? 1 :
// get_random_seed())` :745 — encode-era machinery, cite-never-land.
// :748-:752 tterm — the tterm slot SET (tterm=1): `delete thread_rand;`
// :750 + the :751 nullptr reset.
// :754-:755 `static Codec* ctor(Module*)` — SET, the Module* IGNORED
// (the drift cite vs cd_mpls :347-:355 config carry; lands Ipv4Codec::
// ctor above); :757-:758 `static void dtor(Codec* cd) { delete cd; }`
// SET.

/// :760-:780 `static const CodecApi ipv4_api` — the base slots :763-:772
/// then pinit/pterm/tinit/tterm/ctor/dtor :774-:779 (the `// pinit` etc
/// slot comments land as the TRUE arms — ALL FOUR init/term slots are
/// non-null in C: ginit/gterm/tinit/tterm :724-:752, the faceA PIN
/// `ipv4 tinit=1 tterm=1`). NAME/HELP slots :769/:770 land the :47/:49
/// macro faces (the ADD_DLT-splitted HELP).
pub const IPV4_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // :763
    size: CDAPI_SIZEOF_CODEC_API, // :764 `sizeof(CodecApi)` = 112 (faceA size pin, uniform)
    api_version: CDAPI_VERSION, // :765 1900547
    version: 0, // :766
    features: PLUGIN_SO_RELOAD, // :767
    options: API_OPTIONS, // :768
    name: CD_IPV4_NAME, // :769 -> "ipv4"
    help: CD_IPV4_HELP, // :770 -> the DLT-228 splice (module doc)
    mod_ctor: true, // :771 SET (mod_ctor :718 REAL)
    mod_dtor: true, // :772 SET (mod_dtor :721 REAL)
    pinit: true, // :774 SET (ipv4_codec_ginit :724 — `// pinit`)
    pterm: true, // :775 SET (ipv4_codec_gterm :735 — `// pterm`)
    tinit: true, // :776 SET (ipv4_codec_tinit :743 — `// tinit`; faceA PIN)
    tterm: true, // :777 SET (ipv4_codec_tterm :748 — `// tterm`; faceA PIN)
    ctor: true, // :778 SET  // ctor (:754, Module IGNORED — the drift cite)
    dtor: true, // :779 SET  // dtor (:757)
};

/// :782-:790 the hidden export, TRUE-NAME: `#ifdef BUILDING_SO` :782 /
/// SO arm `SO_PUBLIC const BaseApi* snort_plugins[] =` :783 / `#else`
/// :784 / the static-build `const BaseApi* cd_ipv4[] =` :785 feeding
/// `&ipv4_api.base` :788 + nullptr :789 (ONE feed — faceA `LOAD ipv4` +
/// LOADS 1). nm: `cd_ipv4` D EXACTLY-1 == FILE base (the equality-pin
/// law; NO drift refusal needed at this row — the api STRUCT name
/// ipv4_api split is the C-struct-name rule face, the TABLE name holds).
pub const CD_IPV4: CodecTable = &[&IPV4_API];