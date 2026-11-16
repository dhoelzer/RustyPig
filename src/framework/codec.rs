// Literal transcription of framework/codec.{h,cc} (row 4 milestone),
// validated byte-for-byte against tools/codec_harness/vectors.txt
// (md5 28c79a7f88c840e297d3e19af3c2bb06) and the upstream [buffer] Catch
// gate (4 cases / 10 assertions compiled from the ORIGINAL codec.cc
// UNIT_TEST block).
//
// Structural deviations (also in KNOWN DEVIATIONS.md):
//  * CodecData/EncState drop the const SnortConfig*/ip::IpApi& pointers
//    (never read in the pinned vectors); RawData drops daq_msg (DAQ is a
//    later row). Codec::PKT_MAX and the CDAPI_VERSION plugin struct
//    accompany their layers.
//  * Buffer: ported literally with the same field layout (base/end/max_len/
//    off); the C 'base starts one byte past the array' identity is kept.
//  * IpProtocol/ProtocolId: C declares several enumerators with the SAME
//    value (IP == HOPOPTS == ETHERTYPE_NOT_SET == 0, PROTO_NOT_SET ==
//    RESERVED == PORT_SCAN == 255, IpProtocol/ProtocolId numerics overlap
//    for the cast in IPV6ExtensionOrder). Rust enums force unique
//    discriminants, so these are NEWTYPES (u8/u16 + consts) to preserve
//    the aliases and the cast exactly.

// ---- codecs/codec_module.h (values pinned verbatim; full enum ships with
// the codecs row) ----
pub const GID_DECODE: u32 = 116;
pub const DECODE_IPV6_TRUNCATED_EXT: u32 = 272;
pub const DECODE_IPV6_BAD_OPT_TYPE: u32 = 279;
pub const DECODE_IPV6_BAD_OPT_LEN: u32 = 295;
pub const DECODE_IPV6_UNORDERED_EXTENSIONS: u32 = 296;

// ---- framework/codec.h constants (verbatim) ----
pub const MIN_TTL: u8 = 64;
pub const MAX_TTL: u8 = 255;

pub const CODEC_DF: u16 = 0x0001;
pub const CODEC_UNSURE_ENCAP: u16 = 0x0002;
pub const CODEC_SAVE_LAYER: u16 = 0x0004;
pub const CODEC_ENCAP_LAYER: u16 = CODEC_SAVE_LAYER | CODEC_UNSURE_ENCAP;
pub const CODEC_ROUTING_SEEN: u16 = 0x0008;
pub const CODEC_IPOPT_RR_SEEN: u16 = 0x0010;
pub const CODEC_IPOPT_RTRALT_SEEN: u16 = 0x0020;
pub const CODEC_IPOPT_LEN_THREE: u16 = 0x0040;
pub const CODEC_TEREDO_SEEN: u16 = 0x0080;
pub const CODEC_STREAM_REBUILT: u16 = 0x0100;
pub const CODEC_NON_IP_TUNNEL: u16 = 0x0200;
pub const CODEC_IP6_EXT_OOO: u16 = 0x0400;
pub const CODEC_IP6_BAD_OPT: u16 = 0x0800;
pub const CODEC_ETHER_NEXT: u16 = 0x1000;
pub const CODEC_COMPOUND: u16 = 0x2000;
// C quirk, kept EXACT: spelled 0x400 (duplicates CODEC_IP6_EXT_OOO's bit),
// not 0x4000 as the neighbours suggest (codec.h LAYERS_EXCEEDED line).
pub const CODEC_LAYERS_EXCEEDED: u16 = 0x400;
pub const CODEC_IPOPT_FLAGS: u16 =
    CODEC_IPOPT_RR_SEEN | CODEC_IPOPT_RTRALT_SEEN | CODEC_IPOPT_LEN_THREE;

pub const COMPOUND_LAYERS_MAX: usize = 8;

// Codec::PKT_MAX = 14 + 4 + 1500 + 65535
pub const PKT_MAX: u32 = 14 + 4 + 1500 + 65535;

pub type EncodeFlags = u64;
pub const ENC_FLAG_FWD: EncodeFlags = 0x8000_0000_0000_0000;
pub const ENC_FLAG_SEQ: EncodeFlags = 0x4000_0000_0000_0000;
pub const ENC_FLAG_ID: EncodeFlags = 0x2000_0000_0000_0000;
pub const ENC_FLAG_NET: EncodeFlags = 0x1000_0000_0000_0000;
pub const ENC_FLAG_DEF: EncodeFlags = 0x0800_0000_0000_0000;
pub const ENC_FLAG_RAW: EncodeFlags = 0x0400_0000_0000_0000;
pub const ENC_FLAG_PAY: EncodeFlags = 0x0200_0000_0000_0000;
pub const ENC_FLAG_PSH: EncodeFlags = 0x0100_0000_0000_0000;
pub const ENC_FLAG_FIN: EncodeFlags = 0x0080_0000_0000_0000;
pub const ENC_FLAG_TTL: EncodeFlags = 0x0040_0000_0000_0000;
pub const ENC_FLAG_INLINE: EncodeFlags = 0x0020_0000_0000_0000;
pub const ENC_FLAG_RST_CLNT: EncodeFlags = 0x0010_0000_0000_0000;
pub const ENC_FLAG_RST_SRVR: EncodeFlags = 0x0008_0000_0000_0000;
pub const ENC_FLAG_VAL: EncodeFlags = 0x0000_0000_FFFF_FFFF;
pub const ENC_PROTO_UNSET: u8 = 0xFF;

pub type UpdateFlags = u8;
pub const UPD_COOKED: UpdateFlags = 0x01;
pub const UPD_MODIFIED: UpdateFlags = 0x02;
pub const UPD_RESIZED: UpdateFlags = 0x04;
pub const UPD_REBUILT_FRAG: UpdateFlags = 0x08;

// ---- protocol_ids.h subset (newtypes to keep C's aliased enumerators) ----
// Only the enumerators codec.{h,cc} touches; full tables land with the
// codecs row.
#[allow(dead_code)]
pub mod ip_protocol {
    pub type IpProtocol = u8;
    pub const IP: IpProtocol = 0;
    pub const HOPOPTS: IpProtocol = 0; // same value as IP in C
    pub const ICMPV4: IpProtocol = 1;
    pub const IGMP: IpProtocol = 2;
    pub const IPIP: IpProtocol = 4;
    pub const TCP: IpProtocol = 6;
    pub const UDP: IpProtocol = 17;
    pub const IPV6: IpProtocol = 41;
    pub const ROUTING: IpProtocol = 43;
    pub const FRAGMENT: IpProtocol = 44;
    pub const GRE: IpProtocol = 47;
    pub const ESP: IpProtocol = 50;
    pub const AUTH: IpProtocol = 51;
    pub const SWIPE: IpProtocol = 53;
    pub const MOBILITY: IpProtocol = 55;
    pub const ICMPV6: IpProtocol = 58;
    pub const NONEXT: IpProtocol = 59;
    pub const DSTOPTS: IpProtocol = 60;
    pub const SUN_ND: IpProtocol = 77;
    pub const PIM: IpProtocol = 103;
    pub const PGM: IpProtocol = 113;
    pub const MOBILITY_IPV6: IpProtocol = 135;
    pub const MPLS_IP: IpProtocol = 137;
    pub const MIN_UNASSIGNED_IP_PROTO: IpProtocol = 143;
    pub const RESERVED: IpProtocol = 255;
    pub const PORT_SCAN: IpProtocol = 255;
    pub const PROTO_NOT_SET: IpProtocol = 255;
}

#[allow(dead_code)]
pub mod protocol_id {
    pub type ProtocolId = u16;
    pub const ETHERTYPE_NOT_SET: ProtocolId = 0;
    pub const IP: ProtocolId = 0;
    pub const HOPOPTS: ProtocolId = 0; // aliases both above in C
    pub const ICMPV4: ProtocolId = 1;
    pub const IGMP: ProtocolId = 2;
    pub const IPIP: ProtocolId = 4;
    pub const TCP: ProtocolId = 6;
    pub const UDP: ProtocolId = 17;
    pub const IPV6: ProtocolId = 41;
    pub const ROUTING: ProtocolId = 43;
    pub const FRAGMENT: ProtocolId = 44;
    pub const GRE: ProtocolId = 47;
    pub const ESP: ProtocolId = 50;
    pub const AUTH: ProtocolId = 51;
    pub const SWIPE: ProtocolId = 53;
    pub const MOBILITY: ProtocolId = 55;
    pub const ICMPV6: ProtocolId = 58;
    pub const NONEXT: ProtocolId = 59;
    pub const DSTOPTS: ProtocolId = 60;
    pub const SUN_ND: ProtocolId = 77;
    pub const PIM: ProtocolId = 103;
    pub const PGM: ProtocolId = 113;
    pub const MOBILITY_IPV6: ProtocolId = 135;
    pub const MPLS_IP: ProtocolId = 137;
    pub const PROTO_NOT_SET: ProtocolId = 255;
    pub const ETHERTYPE_MAX: ProtocolId = 0xFFFF; // full enum later row
}

pub use ip_protocol::IpProtocol;
pub use protocol_id::ProtocolId;

// ---- protocols/ipv6.h values used here (verbatim numerics) ----
#[allow(dead_code)]
pub mod hop_by_hop {
    pub type HopByHopOptions = u8;
    pub const PAD1: HopByHopOptions = 0x00;
    pub const PADN: HopByHopOptions = 0x01;
    pub const TUNNEL_ENCAP: HopByHopOptions = 0x04;
    pub const RTALERT: HopByHopOptions = 0x05;
    pub const QUICK_START: HopByHopOptions = 0x06;
    pub const CALIPSO: HopByHopOptions = 0x07;
    pub const JUMBO: HopByHopOptions = 0xC2;
    pub const ENDPOINT_IDENT: HopByHopOptions = 0x8A;
    pub const HOME_ADDRESS: HopByHopOptions = 0xC9;
}
pub use hop_by_hop::HopByHopOptions;

// IP6Extension layout (ipv6.h): ip6e_nxt(0), ip6e_len(1), options...
// The checks read these as raw bytes (reinterpret_cast in C).

#[derive(Copy, Clone)]
pub struct RawData<'a> {
    pub data: &'a [u8],
    pub len: u32, // C uint32_t; probe pins this separate from data.len()
}

#[derive(Copy, Clone)]
pub struct CompoundLayer {
    pub proto_bits: u32,
    // Layer (the parsed-layer handle) ships with the packet layers.
}

#[allow(dead_code)]
pub struct CodecData<'c> {
    pub conf: Option<&'c crate::parser::parse_conf::SnortConfig>,

    // Reset before every decode():
    pub next_prot_id: ProtocolId,
    pub lyr_len: u16,
    pub invalid_bytes: u16,
    pub proto_bits: u32,

    // Codec-specific fields:
    pub codec_flags: u16,
    pub ip_layer_cnt: u8,
    pub ip6_extension_count: u8,
    pub curr_ip6_extension: u8,
    pub ip6_csum_proto: IpProtocol,
    pub tunnel_bypass: bool,

    pub compound_layers: [Option<CompoundLayer>; COMPOUND_LAYERS_MAX],
    pub compound_layer_cnt: u8,
}

impl<'c> CodecData<'c> {
    pub fn new(
        sc: Option<&'c crate::parser::parse_conf::SnortConfig>,
        init_prot: ProtocolId,
    ) -> CodecData<'c> {
        CodecData {
            conf: sc,
            next_prot_id: init_prot,
            lyr_len: 0,
            invalid_bytes: 0,
            proto_bits: 0,
            codec_flags: 0,
            ip_layer_cnt: 0,
            ip6_extension_count: 0,
            curr_ip6_extension: 0,
            ip6_csum_proto: ip_protocol::IP,
            tunnel_bypass: false,
            compound_layers: [None; COMPOUND_LAYERS_MAX],
            compound_layer_cnt: 0,
        }
    }

    #[inline]
    #[allow(non_snake_case)]
    pub fn is_cooked(&self) -> bool {
        (self.codec_flags & CODEC_STREAM_REBUILT) != 0
    }
}

// EncState: same fields minus the const IpApi& ref (unused in pinned
// vectors; re-add with the encode layer).
#[allow(dead_code)]
pub struct EncState {
    pub flags: EncodeFlags,
    pub dsize: u16,
    pub next_ethertype: ProtocolId,
    pub next_proto: IpProtocol,
    pub ttl: u8,
}

impl EncState {
    pub fn new(
        f: EncodeFlags,
        pr: IpProtocol,
        t: u8,
        data_size: u16,
    ) -> EncState {
        EncState {
            flags: f,
            dsize: data_size,
            // ctor init-list order pins these:
            next_ethertype: protocol_id::ETHERTYPE_NOT_SET,
            next_proto: pr,
            ttl: t,
        }
    }

    #[inline]
    #[allow(non_snake_case)]
    pub fn next_proto_set(&self) -> bool {
        self.next_proto != ip_protocol::PROTO_NOT_SET
    }
    #[inline]
    #[allow(non_snake_case)]
    pub fn ethertype_set(&self) -> bool {
        self.next_ethertype != protocol_id::ETHERTYPE_NOT_SET
    }
    #[inline]
    pub fn forward(&self) -> bool {
        (self.flags & ENC_FLAG_FWD) != 0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::needless_return)] // literal C flow kept readable, see tail
    pub fn get_ttl(&self, lyr_ttl: u8) -> u8 {
        if self.forward() {
            if self.flags & ENC_FLAG_TTL != 0 {
                return self.ttl;
            } else {
                return lyr_ttl;
            }
        } else {
            // C: MAX_TTL - lyr_ttl is int arithmetic; uint8_t result.
            let mut new_ttl: u16 = if self.flags & ENC_FLAG_TTL != 0 {
                self.ttl as u16
            } else {
                (MAX_TTL as u16) - lyr_ttl as u16
            };
            if new_ttl < MIN_TTL as u16 {
                new_ttl = MIN_TTL as u16;
            }
            new_ttl as u8
        }
    }
}

// C: base starts at buf+size, i.e. one PAST the array end (identity kept;
// vectors pin off = data()-base_lo, so off == the C base index).
pub struct Buffer<'a> {
    base: usize, // C pointer 'base'; we keep it as an index into store
    end: u32,    // end of data
    max_len: u32,
    pub off: u32, // public in C; allocate() does NOT touch it
    store: &'a mut [u8],
}

impl<'a> Buffer<'a> {
    pub fn new(buf: &'a mut [u8], size: u32) -> Buffer<'a> {
        Buffer {
            // Buffer(uint8_t* buf, uint32_t size) : base(buf + size), end(0), ...
            base: size as usize,
            end: 0,
            max_len: size,
            off: 0,
            store: buf,
        }
    }

    // C data() const returns uint8_t*; we mirror via an index because the
    // probe prints (data() - raw_base) only, so the index IS the pinned
    // quantity. data()[..size()] is the live region.
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    pub fn data_off(&self) -> usize {
        self.base
    }
    pub fn data(&self) -> Option<&[u8]> {
        if self.end == 0 {
            // C says the pointer is INVALID when size is 0 (it points one
            // byte past the array); Rust hands back None for that state and
            // &store[base..base+end] when valid.
            return None;
        }
        Some(&self.store[self.base..self.base + self.end as usize])
    }
    #[inline]
    pub fn size(&self) -> u32 {
        self.end
    }

    #[inline]
    pub fn allocate(&mut self, len: u32) -> bool {
        if (self.end + len) > self.max_len {
            return false;
        }
        self.end += len;
        self.base -= len as usize;
        true
    }

    #[inline]
    pub fn clear(&mut self) {
        self.base += self.end as usize;
        self.end = 0;
        self.off = 0;
    }
}

// ---- the two protected Codec check methods (free functions; the probe
// reaches them via 'using', so they carry the exact same code) ----

// C: DetectionEngine::queue_event(GID_DECODE, sid) — the harness witness
// prints 'EV gid sid'; the Rust port takes a sink callback so the replay
// observes the identical ordering, and production wires queue_event later.
pub type QueueSink<'a> = &'a mut dyn FnMut(u32, u32);

#[allow(non_snake_case)]
fn codec_event(_codec: &CodecData, sid: u32, sink: QueueSink) {
    sink(GID_DECODE, sid);
}

// RFC 8200 section 4.2 (verbatim static helper).
#[inline]
fn ip6_opt_receiver_skips(type_byte: HopByHopOptions) -> bool {
    const IP6_OPT_ACTION_MASK: u8 = 0xc0;
    (type_byte & IP6_OPT_ACTION_MASK) == 0
}

// C quirk kept EXACT: the switch's default case FALLS THROUGH into the
// TLV check (no break between default and the first listed case), and a
// type outside the enum still hits default (undefined-enum cast is legal
// C); Rust keeps that as an if/else chain plus match on the enumerators.
// Second quirk: `if (raw.len < total_octets)` queues TRUNCATED but does
// NOT return — the walk continues over the short buffer (pinned: H6 emits
// 'EV 272' then 'EV 295' and returns true via the skips path).
#[allow(non_snake_case)]
pub fn check_ipv6_hop_options(
    raw: &RawData<'_>,
    codec: &mut CodecData<'_>,
    sink: QueueSink,
) -> bool {
    // reinterpret_cast<const ip::IP6Extension*>(raw.data): ip6e_len is
    // byte 1. C reads without bounds checks (real decoders always hand it
    // an extension header). Every pinned vector feeds >= 8 bytes, so the
    // .get-or-0 below never fires in replay; it exists only so short
    // inputs panic-free instead of UB. The truncated case does NOT return
    // (pinned H6: 'EV 272' then 'EV 295' then true via skips).
    let exthdr = raw.data;
    let total_octets: u32 = (*exthdr.get(1).unwrap_or(&0) as u32) * 8 + 8;

    if raw.len < total_octets {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, sink);
    }

    let hdr_end: usize = total_octets as usize;
    let pkt_array = raw.data;

    let mut pkt: usize = 2; // /* Skip to the options */
    let mut oplen: u8;

    /* Iterate through the options, check for bad ones */
    while pkt < hdr_end {
        let t = pkt_array[pkt];
        // switch (type): PAD1 ++; default: (event + latch) FALL THRU and
        // join the listed-enumerator block below.
        match t {
            hop_by_hop::PAD1 => {
                pkt += 1;
                continue;
            }
            hop_by_hop::PADN
            | hop_by_hop::JUMBO
            | hop_by_hop::RTALERT
            | hop_by_hop::TUNNEL_ENCAP
            | hop_by_hop::QUICK_START
            | hop_by_hop::CALIPSO
            | hop_by_hop::HOME_ADDRESS
            | hop_by_hop::ENDPOINT_IDENT => {}
            _ => {
                // default: !(codec_flags & CODEC_IP6_BAD_OPT) -> event +
                // latch, then FALL THRU into the TLV check (pinned H3/H4).
                if codec.codec_flags & CODEC_IP6_BAD_OPT == 0 {
                    codec_event(codec, DECODE_IPV6_BAD_OPT_TYPE, sink);
                    codec.codec_flags |= CODEC_IP6_BAD_OPT;
                }
                // fall thru ...
            }
        }

        // Ensure the length byte is within the header and the whole TLV
        // option fits inside it. C reads *(pkt+1) even when pkt+1 >=
        // hdr_end inside the OR (short-circuit: first operand true skips
        // the read; Rust && likewise).
        if (pkt + 1) >= hdr_end
            || (hdr_end - pkt) < (*pkt_array.get(pkt + 1).unwrap_or(&0) as usize + 2)
        {
            codec_event(codec, DECODE_IPV6_BAD_OPT_LEN, sink);
            return ip6_opt_receiver_skips(t);
        }
        oplen = pkt_array[pkt + 1];
        pkt += 1; // C: ++pkt inside oplen assignment
        pkt += (oplen as usize) + 1;
    }

    true
}

// NOTE:: codec.next_prot_id MUST be set before calling (pinned semantics)
#[allow(non_snake_case)]
pub fn check_ipv6_extension_order(
    codec: &mut CodecData<'_>,
    ip_proto: IpProtocol,
    sink: QueueSink,
) {
    let current_order: usize = ipv6_extension_order(ip_proto);

    if current_order <= codec.curr_ip6_extension as usize {
        let next_order = ipv6_id_extension_order(codec.next_prot_id);

        /* A second "Destination Options" header is allowed iff:
           1) A routing header was already seen, and
           2) The second destination header is the last one before the
              upper layer.
        */
        // literal C nesting kept (clippy::collapsible_if suppressed: the
        // upstream shape is two ifs, keep it diff-evident).
        #[allow(clippy::collapsible_if)]
        if !((codec.codec_flags & CODEC_ROUTING_SEEN != 0)
            && (ip_proto == ip_protocol::DSTOPTS)
            && (next_order == ipv6::IPV6_ORDER_MAX))
        {
            if codec.codec_flags & CODEC_IP6_EXT_OOO == 0 {
                codec_event(codec, DECODE_IPV6_UNORDERED_EXTENSIONS, sink);
                codec.codec_flags |= CODEC_IP6_EXT_OOO;
            }
        }
    } else {
        codec.curr_ip6_extension = current_order as u8;
    }

    if ip_proto == ip_protocol::ROUTING {
        codec.codec_flags |= CODEC_ROUTING_SEEN;
    }
}

// ---- protocols/ipv6.h order tables (verbatim: Reflects the recommended
// IPv6 order in RFC 2460 4.1) ----
pub mod ipv6 {
    pub const IPV6_ORDER_MAX: usize = 7;

    #[allow(non_snake_case)]
    pub fn ipv6_id_extension_order(prot_id: crate::framework::codec::ProtocolId) -> usize {
        use crate::framework::codec::protocol_id::*;
        match prot_id {
            HOPOPTS => 1,
            DSTOPTS => 2,
            ROUTING => 3,
            FRAGMENT => 4,
            AUTH => 5,
            ESP => 6,
            _ => IPV6_ORDER_MAX,
        }
    }

    #[allow(non_snake_case)]
    pub fn ipv6_extension_order(ip_proto: crate::framework::codec::IpProtocol) -> usize {
        // C: IPV6IdExtensionOrder((ProtocolId)ip_proto) — newtypes make
        // the cast a widening identity.
        ipv6_id_extension_order(ip_proto as crate::framework::codec::ProtocolId)
    }
}
pub use ipv6::{ipv6_extension_order, ipv6_id_extension_order, IPV6_ORDER_MAX};
