//! Port of `src/codecs/root/cd_eth.cc` (262 L) — row 18d.
//! Ground: snort3-src @ fe29cbe, md5 `22f10ceb0e01ab6c505534bde42c04aa`
//! (eth PLAN §0). The root ethernet link-layer codec: the DLT ladder
//! (cc:74-:78), the ethertype dispatch (cc:85-:121), the log/encode/
//! format/update arms, and the exported `cd_eth[]` table (cc:253-:261).
//!
//! vectors pins (tools/eth_harness/vectors.txt, 15 L, md5
//! 1bd98dbb57dd2f536104995bd76d9bad — IMMUTABLE, eth PLAN §3):
//!   vec:1  `API eth type=0 size=112 ver=1900547 name=eth`
//!   vec:2  `HELP support for ethernet protocol (DLT 1) (DLT 51)` —
//!          the ADD_DLT LADDER x2 (the cc:38 nesting) = the daq_dlt
//!          graft's SECOND consumer (consistency pin vs 18c's raw
//!          DLT_RAW 12 face)
//!   vec:3  `EV 116 424` — DECODE_ETH_HDR_TRUNC, the enum WALK pin:
//!          418 DECODE_ICMP4_TYPE_OTHER at codec_module.h:171 + six
//!          unnumbered entries :172-:176 -> :177 = 424 (the WALK half
//!          of the double-pin discipline; cd_arp's 109 lands by
//!          LITERAL at h:73)
//!   vec:4  `ETH short -> 0` (12 B < ETH_HEADER_LEN 14)
//!   vec:5  `ETH v4 -> 1 next=2048 lyr=14 bits=2048` (PROTO_BIT__ETH
//!          0x000800, decode_data.h:98 — decimal posture; 0x0800
//!          answers TWICE, ethertype AND the proto_bits OR)
//!   vec:6  `ETH llc -> 1 next=263` (0x0005 <= ETHERTYPE_MINIMUM
//!          0x0600, protocol_ids.h:143 -> ETHERNET_LLC 0x0107, :134)
//!   vec:7/:8 `DLT 51` BEFORE `DLT 1` — the PUSH ORDER cc:76-:77
//!   vec:9  `PIDS 261 n=1` (ETHERNET_802_3 0x0105, protocol_ids.h:132)
//!
//! daq_dlt graft EXTENSION (eth PLAN §1): `DLT_EN10MB 1` = the-
//! tcpdump-group/libpcap master `pcap/dlt.h:68`; `DLT_PPP_ETHER 51` =
//! master `pcap/dlt.h:243` (fetched THIS row — the 18c android mirror
//! cite 404s, corrected in the graft header + build.sh greps).
//!
//! log/encode/format/update: the probe face NEVER calls them (eth
//! PLAN §3 arms list) — literal port-by-reading, every move cited to
//! its C lines, exercised by Rust-side arms in tests/eth_parity_test.
//! rs only (deviations row 18d "port-by-reading arms").

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    ip_protocol, protocol_id, API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    CodecApiRecord, CodecData, EncState, PLUGIN_SO_RELOAD, PT_CODEC, PROTO_BIT__ETH, QueueSink,
    RawData, ENC_FLAG_RAW,
};

/// daq_dlt.h graft values (module doc + harness graft header carry the
/// libpcap master cites; eth PLAN §1).
pub const DLT_EN10MB: i32 = 1;
pub const DLT_PPP_ETHER: i32 = 51;

/// eth.h:37 `constexpr uint16_t ETH_HEADER_LEN = 14;`
pub const ETH_HEADER_LEN: u16 = 14;

/// cc:36 `#define CD_ETH_NAME "eth"`
pub const CD_ETH_NAME: &str = "eth";
/// cc:37 `#define CD_ETH_HELP_STR "support for ethernet protocol"`
pub const CD_ETH_HELP_STR: &str = "support for ethernet protocol";
/// cc:38 `#define CD_ETH_HELP ADD_DLT(ADD_DLT(CD_ETH_HELP_STR,
/// DLT_EN10MB), DLT_PPP_ETHER)` — codec.h:52 compile-time splice at
/// the graft values: vectors:2 `support for ethernet protocol
/// (DLT 1) (DLT 51)`. The NESTING order — EN10MB inner, PPP_ETHER
/// outer — is the ladder: add_dlt(add_dlt(help, 1), 51); the parity
/// test re-composes it so the literal can never drift from the
/// graft constants (18c's add_dlt fn in cd_raw.rs rides unchanged).
pub const CD_ETH_HELP: &str = "support for ethernet protocol (DLT 1) (DLT 51)";

/// cc:42-:46 `static const RuleMap eth_rules[]` — one row + the
/// `{ 0, nullptr }` terminator (message-slot posture of the landed
/// rule tables, 18a FMOD_RULES precedent; the sids reference the
/// 18d enum walk).
pub const ETH_RULES: [(u32, &str); 2] = [
    (CodecSid::DECODE_ETH_HDR_TRUNC as u32, "truncated ethernet header"), // cc:44 (walk = 424)
    (0, ""), // cc:45
];

/// cc:48-:55 `class EthModule : public BaseCodecModule` — the ctor
/// face (BaseCodecModule(CD_ETH_NAME, CD_ETH_HELP), h:243); no Rust
/// Module base fork (17z/18a posture), the gid=116 readback rides the
/// landed BaseCodecModule (codec_module.rs).
#[derive(Default)]
pub struct EthModule;

impl EthModule {
    pub fn new() -> EthModule {
        EthModule
    }
    /// cc:53-:54 `get_rules() { return eth_rules; }`
    pub fn get_rules() -> &'static [(u32, &'static str); 2] {
        &ETH_RULES
    }
}

/// cc:57-:71 `class EthCodec : public Codec` — the override set
/// (get_protocol_ids/get_data_link_type/log/decode/encode/format/
/// update).
#[derive(Default)]
pub struct EthCodec;

impl EthCodec {
    /// cc:60 `EthCodec() : Codec(CD_ETH_NAME) { }`
    pub fn new() -> EthCodec {
        EthCodec
    }

    /// eth.h:46-:47 `ethertype() const { return (ProtocolId)
    /// ntohs(ether_type); }` over eth.h:39-:43 EtherHdr — ether_dst
    /// at 0..6, ether_src at 6..12, ether_type (uint16_t, NET order
    /// on the wire) at 12..14. The Rust port reads the big-endian
    /// u16 off the wire (ntohs == BE read on LE hosts).
    #[inline]
    pub fn ethertype(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[12], pkt[13]])
    }

    /// cc:74-:78 `get_data_link_type`: emplace_back(DLT_PPP_ETHER)
    /// THEN emplace_back(DLT_EN10MB) — the push order is PINNED:
    /// vectors:7 `DLT 51` BEFORE vectors:8 `DLT 1` (the ladder is
    /// the inverse of the HELP-nesting order cc:38 — kept EXACT).
    pub fn get_data_link_type(&self, v: &mut Vec<i32>) {
        v.push(DLT_PPP_ETHER); // cc:76
        v.push(DLT_EN10MB); // cc:77
    }

    /// cc:80-:83 `get_protocol_ids`: ETHERNET_802_3 (0x0105 = 261,
    /// protocol_ids.h:132) — vectors:9 `PIDS 261 n=1`.
    pub fn get_protocol_ids(&self, v: &mut Vec<u16>) {
        v.push(protocol_id::ETHERNET_802_3); // cc:82
    }

    /// cc:85-:121 out-of-line decode. The DecodeData& operand is
    /// NEVER READ in the body (cc:85 unnamed param — the never-read
    /// posture of 18c's decode arms; the sink stands for the event
    /// raise exactly as in 18c).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink) -> bool {
        // cc:87-:91 `if (raw.len < eth::ETH_HEADER_LEN)` -> event +
        // false. vectors:3/:4 `EV 116 424` then `ETH short -> 0` —
        // and NO field mutation on this arm (returns before the
        // reinterpret_cast).
        if raw.len < ETH_HEADER_LEN as u32 {
            crate::framework::codec::codec_event(codec, CodecSid::DECODE_ETH_HDR_TRUNC as u32, sink);
            return false;
        }

        // cc:94-:96 the EtherHdr overlay + ethertype() (net-order read).
        let next_prot = Self::ethertype(raw.data);

        // cc:97-:102 `to_utype(next_prot) <= to_utype(ProtocolId::
        // ETHERTYPE_MINIMUM)` — the LLC arm (0x0600 = 1536;
        // protocol_ids.h:143). vectors:6 `ETH llc -> 1 next=263`.
        if (next_prot as u32) <= (protocol_id::ETHERTYPE_MINIMUM as u32) {
            codec.next_prot_id = protocol_id::ETHERNET_LLC; // cc:99
            codec.lyr_len = ETH_HEADER_LEN; // cc:100
            codec.proto_bits |= PROTO_BIT__ETH; // cc:101
        }
        // cc:103-:112 FabricPath arm: next stays the raw ethertype
        // and lyr_len is ZERO — the first 16 bytes are FabricPath
        // data, and FabricPath sends the decoder back (comment
        // cc:105-:109); NOTE proto_bits is NOT set on this arm (the
        // ONLY arm without the OR — literal operand per-arm audit).
        // Vectors silent; port-by-reading, exercised by the FPATH
        // unit arm (cites cc:110-:111).
        else if next_prot == protocol_id::ETHERTYPE_FPATH {
            codec.next_prot_id = next_prot; // cc:110
            codec.lyr_len = 0; // cc:111
        }
        // cc:113-:118 ordinary arm: vectors:5 `ETH v4 -> 1
        // next=2048 lyr=14 bits=2048` (0x0800 twice: the ethertype
        // AND PROTO_BIT__ETH 0x000800).
        else {
            codec.proto_bits |= PROTO_BIT__ETH; // cc:115
            codec.lyr_len = ETH_HEADER_LEN; // cc:116
            codec.next_prot_id = next_prot; // cc:117
        }

        // cc:120
        true
    }

    /// cc:123-:136 log. Harness face (eth PLAN §2): the REAL
    /// LogEthAddrs body (log/log_text.cc:112) was EXCLUDED from the
    /// link — it drags packet/appid/sfdaq — the harness witnesses a
    /// 1-line stand-in and the probe never calls log() at all. Rust
    /// posture (deviations row 18d "log_text seam"): the LogEthAddrs
    /// seam is a documented silent step and TextLog_Print's formatted
    /// fragments reach an ordered sink; format strings literal:
    /// cc:133 `"  len:0x%04X"` / cc:135 `"  type:0x%04X"` (%04X ->
    /// upper-case 4-hex; the two leading spaces kept byte-exact).
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        // cc:126 the EtherHdr overlay, cc:128 `LogEthAddrs(text_log,
        // eh);` — witness stand-in: NO fragment under this face.
        let _ = raw_pkt;

        // cc:130 `const ProtocolId prot_id = eh->ethertype();`
        let prot_id = Self::ethertype(raw_pkt);

        // cc:132-:135 the SAME <= ETHERTYPE_MINIMUM test re-
        // evaluated (to_utype on both sides), different arms:
        // the llc face prints `len:`, the normal face `type:`.
        if (prot_id as u32) <= (protocol_id::ETHERTYPE_MINIMUM as u32) {
            sink(format!("  len:0x{prot_id:04X}")); // cc:133
        } else {
            sink(format!("  type:0x{prot_id:04X}")); // cc:135
        }
    }

    /// cc:142-:189 encode. Vectors NEVER reach it (eth PLAN §3 arms
    /// list) — literal port-by-reading; each move cited. The
    /// `SnortConfig*` comes in as Option<&SnortConfig> (C's
    /// unguarded `SnortConfig::get_conf()` at cc:164 — cd_eth.cc is
    /// the codecs tree's FIRST get_conf consumer, eth PLAN §2;
    /// None models the zeroed witness config — snort_config.h:289
    /// `uint8_t* eth_dst = nullptr` -> the new SnortConfig.eth_dst:
    /// Option, deviations row 18c "conf-None" posture). The `Flow*`
    /// operand is UNNAMED in C (cc:143) — dropped like the other
    /// never-read pointer operands. `raw_len` unnamed too (cc:142).
    #[allow(clippy::needless_return)] // literal C flow kept readable
    pub fn encode(
        &self,
        raw_in: &[u8],
        _raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
        conf: Option<&crate::parser::parse_conf::SnortConfig>,
    ) -> bool {
        // cc:145 the EtherHdr overlay hi; cc:147-:148 `hi->
        // ethertype() == ETHERTYPE_FPATH` -> true (FabricPath data
        // is re-encoded by the FPATH codec, not here).
        if Self::ethertype(raw_in) == protocol_id::ETHERTYPE_FPATH {
            return true;
        }

        // cc:151 `bool raw = (enc.flags & ENC_FLAG_RAW);`
        let raw = (enc.flags & ENC_FLAG_RAW) != 0;

        // cc:153 `if ( !raw || (buf.size() != 0) )` — outer-most
        // layer when NOT raw ip, or any encapsulated ethernet layer.
        if !raw || (buf.size() != 0) {
            // cc:157-:158 `if ( !buf.allocate(eth::ETH_HEADER_LEN) )
            // return false;`
            if !buf.allocate(ETH_HEADER_LEN as u32) {
                return false;
            }

            // cc:160 `eth::EtherHdr* ho = (eth::EtherHdr*)buf.data
            // ();` — the fresh 14-byte tail (landed Buffer layout).
            let ho = buf
                .data_mut()
                .expect("allocate(ETH_HEADER_LEN) just made size != 0");

            // cc:161-:162 the TERNARY precedence kept EXACT —
            // htons applies ONLY to the enc.next_ethertype arm:
            //   ho->ether_type = enc.ethertype_set()
            //       ? htons(to_utype(enc.next_ethertype))
            //       : hi->ether_type;
            // so the else-arm copies the RAW wire u16 verbatim (no
            // double-swap).
            if enc.ethertype_set() {
                ho[12..14].copy_from_slice(&enc.next_ethertype.to_be_bytes()); // htons
            } else {
                ho[12..14].copy_from_slice(&raw_in[12..14]); // verbatim wire bytes
            }

            // cc:164 `const SnortConfig* sc = SnortConfig::get_conf
            // ();` — always non-null C-side (the witness static
            // config, eth PLAN §2); its `eth_dst` (snort_config.h:289
            // `uint8_t* eth_dst = nullptr`) is the field the arms
            // read. The Option<&SnortConfig> seam folds both faces
            // (18c conf-None posture): None == zeroed config == a
            // null eth_dst, the MEASURABLE face under the witness.
            let sc_eth_dst: Option<&[u8; 6]> = conf.and_then(|c| c.eth_dst.as_ref());

            // cc:166-:174 forward: src<-hi src; dst<-sc eth_dst if
            // set else hi dst. Offsets eth.h:40-:42 (dst 0..6,
            // src 6..12).
            if enc.forward() {
                ho[6..12].copy_from_slice(&raw_in[6..12]); // cc:168
                if let Some(d) = sc_eth_dst {
                    ho[0..6].copy_from_slice(d); // cc:171
                } else {
                    ho[0..6].copy_from_slice(&raw_in[0..6]); // cc:173
                }
            }
            // cc:175-:183 reverse: src<-hi DST (the swap); dst<-sc
            // eth_dst if set else hi src.
            else {
                ho[6..12].copy_from_slice(&raw_in[0..6]); // cc:177
                if let Some(d) = sc_eth_dst {
                    ho[0..6].copy_from_slice(d); // cc:180
                } else {
                    ho[0..6].copy_from_slice(&raw_in[6..12]); // cc:182
                }
            }
        }

        // cc:186-:187 the reset pair, cc:188 `return true`.
        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET;
        enc.next_proto = ip_protocol::PROTO_NOT_SET;
        true
    }

    /// cc:191-:204 format. Vectors silent — port-by-reading.
    /// `reverse && ethertype() != ETHERTYPE_FPATH` swaps dst/src in
    /// place via the 6-byte tmp (cc:198-:202 — memcpy order:
    /// tmp<-dst, dst<-src, src<-tmp).
    pub fn format(&self, reverse: bool, raw_pkt: &mut [u8]) {
        if reverse && (Self::ethertype(raw_pkt) != protocol_id::ETHERTYPE_FPATH) {
            let mut tmp_addr = [0u8; 6]; // cc:198
            // split_at_mut(6) = the two non-overlapping EtherHdr
            // address fields (eth.h:40-:42 dst 0..6, src 6..12) —
            // aliasing-free spelling of C's three memcpys.
            let (dst, src) = raw_pkt.split_at_mut(6);
            tmp_addr.copy_from_slice(dst); // cc:200 tmp<-dst
            dst.copy_from_slice(&src[..6]); // cc:201 dst<-src
            src[..6].copy_from_slice(&tmp_addr); // cc:202 src<-tmp
        }
    }

    /// cc:206-:213 update. The `const ip::IpApi&` and EncodeFlags
    /// operands are UNNAMED in C (cc:206-:207) — dropped like the
    /// other never-read operands (deviations rows 18c/18d never-read
    /// posture). Vectors silent — port-by-reading: NOT FabricPath ->
    /// `updated_len += lyr_len` (cc:212 — C's `+=` on the uint32_t&).
    pub fn update(&self, raw_pkt: &[u8], lyr_len: u16, updated_len: &mut u32) {
        if Self::ethertype(raw_pkt) != protocol_id::ETHERTYPE_FPATH {
            *updated_len = updated_len.wrapping_add(lyr_len as u32); // cc:212
        }
    }
}

/// cc:219-:229 the four static ctor/dtor faces (mod_ctor/mod_dtor
/// news/deletes EthModule; ctor/dtor EthCodec) — presence-bool slots
/// on the record (17w/18c posture; the probe's ea->ctor(nullptr)
/// mirrors through EthCodec::new in the replay).
///
/// cc:231-:251 `static const CodecApi eth_api` — vectors:1 `API eth
/// type=0 size=112 ver=1900547 name=eth`; the module pair SET
/// (cc:242-:243) — the contrast vs the four 18c no-op records
/// (nullptr mod slots), mod_ctor/mod_dtor true here; the aux four
/// nullptr (cc:245-:248 comments carried verbatim).
pub const ETH_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:234
    size: CDAPI_SIZEOF_CODEC_API, // cc:235 sizeof(CodecApi) == 112 pin
    api_version: CDAPI_VERSION, // cc:236 (== 1900547, vec:1 ver=)
    version: 0,             // cc:237
    features: PLUGIN_SO_RELOAD, // cc:238
    options: API_OPTIONS,   // cc:239
    name: CD_ETH_NAME,      // cc:240
    help: CD_ETH_HELP,      // cc:241 the spliced LADDER face
    mod_ctor: true,         // cc:242 SET (contrast vs 18c)
    mod_dtor: true,         // cc:243 SET
    pinit: false,           // cc:245 `nullptr, // pinit`
    pterm: false,           // cc:246 `nullptr, // pterm`
    tinit: false,           // cc:247 `nullptr, // tinit`
    tterm: false,           // cc:248 `nullptr, // tterm`
    ctor: true,             // cc:249 `ctor, // ctor`
    dtor: true,             // cc:250 `dtor, // dtor`
};

/// cc:253-:261 export (non-BUILDING_SO face; the BUILDING_SO
/// alternation folds exactly like 18c's four TUs — deviations row 18c
/// unchanged). eth PLAN §5 latent note: codec_api.cc:39-:44
/// `STATIC_CODECS` externs cd_eth[] — INACTIVE at the pinned face;
/// if a later row flips it, that extern FREE-resolves to 18d's REAL
/// table, not a stub fork.
pub const CD_ETH: crate::framework::codec::CodecTable = &[&ETH_API];
