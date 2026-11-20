//! Port of `src/codecs/misc/cd_geneve.cc` (282 L) — row 18f.
//! Ground: snort3-src @ fe29cbe, md5 `0d05bf86e27d8c9c0fac63edfb5bc7ed`
//! (tun PLAN §0). DIR FACT: `codecs/misc/`. TRUE NAME: `cd_geneve` at
//! cc:277 (BUILDING_SO ternary face :274-:282) — file base == extern
//! name (tun PLAN §0).
//!
//! MODULE PAIR: GeneveModule : BaseCodecModule (cc:56-:63) + the
//! 5-row `geneve_rules` RuleMap (cc:46-:54) — vectors:38 `GEN rules=5
//! sid0=180 name=geneve` (walk over the h:108-:112 sids 180-184, all
//! landed 18d CodecSid enumerators — NEVER re-walked) +
//! vectors_faceA:5 `API geneve ... name=geneve` (mod_ctor face via the
//! record). RuleMap/rule_count/BaseCodecModule ride the landed homes.
//!
//! THE BYPASS HOOK — LEFT-OPEN (tun PLAN §4/§7, deviations row 18f):
//! cc:166 conf->tunnel_bypass_enabled(TUNNEL_GENEVE) lands as the
//! explicit hook param (same ruling as cd_teredo/cd_gtp).
//!
//! STRUCT-OFFSET FACT (the vectors DISCRIMINATOR — deviations bullet):
//! GeneveHdr is NOT #[repr(packed)] in C but its natural layout is
//! g_vl@0 g_flags@1 g_proto@2-3 g_vni@4-6 g_rsvd@7, sizeof 8
//! (protocols/geneve.h:90-:117). The DEC probe buffer sets
//! h[4]=0x65 h[5]=0x58 — bytes 4-5, the VNI field, NOT g_proto — so
//! hdr->proto() reads 0 and vectors:33 prints `next=0` (the probe's
//! own comment says "proto 0x6558 -> ETHERNET_802_3": the EXPRESSION
//! wins over the comment, skill rule — the emitted face is the pin).
//! The suite fixture (geneve_codec_test.cc:45) sets bytes 2-3 =
//! 0x6558 properly -> GENEVE_ETH_TYPE -> ETHERNET_802_3. This Rust
//! port reads the SAME offsets through accessors over the byte slice
//! (the cd_eth ethertype posture — no repr(C) pun).
//!
//! THE log PAIR (cc:180-:223) + encode (cc:225-:234) are NEVER
//! vectorized (tun PLAN §6: decode/pid/API/rules arms only; the
//! misc/test suite arms decode + the GeneveLyr face only) — literal
//! port-by-reading with cites; the TextLog_Print fragments reach an
//! ordered String sink (the 18d cd_eth log posture).
//!
//! THE GeneveLyr/get_opt_data face (protocols/geneve.h:119-:147):
//! landed HERE row-scoped because the misc/test geneve suites arm it
//! up_geneve_* directly (deviations: 15-path staging). The suite's
//! local get_geneve_opt_data helper lives in the parity test file
//! (suite-local C function, cited there).
//!
//! ROW-SCOPED VOCAB (deviations: 15-path staging): protocol_ids/
//! decode_data/snort_config numerics land HERE with cites;
//! framework/codec.rs and parse_conf.rs byte-UNTOUCHED this row.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CodecApiRecord, CodecTable, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    CODEC_NON_IP_TUNNEL, CodecData, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink,
    RawData,
};

/// cc:33 `#define CD_GENEVE_NAME "geneve"`
pub const CD_GENEVE_NAME: &str = "geneve";
/// cc:34 `#define CD_GENEVE_HELP "support for Geneve: Generic Network
/// Virtualization Encapsulation"` — vectors:2 HELP face.
pub const CD_GENEVE_HELP: &str = "support for Geneve: Generic Network Virtualization Encapsulation";

/// cc:36 `#define RFC_8926_GENEVE_VERSION 0`
pub const RFC_8926_GENEVE_VERSION: u8 = 0;
/// cc:37 `#define GENEVE_ETH_TYPE 0x6558`
pub const GENEVE_ETH_TYPE: u16 = 0x6558;
/// cc:39 `#define GENEVE_FLAG_O 0x80`
pub const GENEVE_FLAG_O: u16 = 0x80;
/// cc:40 `#define GENEVE_FLAG_C 0x40`
pub const GENEVE_FLAG_C: u16 = 0x40;
/// cc:42 `#define GENEVE_OPT_TYPE_C 0x80`
pub const GENEVE_OPT_TYPE_C: u16 = 0x80;

/// cc:46-:54 `static const RuleMap geneve_rules[]` — the 5-row table
/// (all five CodecSid enumerators landed 18d: h:108-:112 -> 180-:184)
/// + the `{ 0, nullptr }` terminator. vectors:38 `GEN rules=5
/// sid0=180 name=geneve`.
pub const GENEVE_RULES: [RuleMap; 6] = [
    RuleMap {
        sid: CodecSid::DECODE_GENEVE_DGRAM_LT_GENEVE_HDR as u32, // 180
        msg: Some("insufficient room for geneve header"), // cc:48 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GENEVE_INVALID_VERSION as u32, // 181
        msg: Some("invalid version"), // cc:49 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GENEVE_INVALID_HEADER as u32, // 182
        msg: Some("invalid header"), // cc:50 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GENEVE_INVALID_FLAGS as u32, // 183
        msg: Some("invalid flags"), // cc:51 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GENEVE_INVALID_OPTIONS as u32, // 184
        msg: Some("invalid options"), // cc:52 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:53 terminator
];

/// cc:56-:63 `class GeneveModule : public BaseCodecModule` —
/// get_rules() override cc:61-:62.
#[derive(Debug)]
pub struct GeneveModule {
    pub base: BaseCodecModule,
}

impl GeneveModule {
    /// cc:59 `GeneveModule() : BaseCodecModule(CD_GENEVE_NAME,
    /// CD_GENEVE_HELP) { }`
    pub fn new() -> GeneveModule {
        GeneveModule {
            base: BaseCodecModule::new(CD_GENEVE_NAME, CD_GENEVE_HELP),
        }
    }

    /// cc:61-:62 `{ return geneve_rules; }`.
    pub fn get_rules() -> &'static [RuleMap] {
        &GENEVE_RULES
    }

    /// vectors:38 `name=geneve`.
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for GeneveModule {
    fn default() -> Self {
        Self::new()
    }
}

// ---- protocols/geneve.h accessor face (byte-slice overlay reads,
// module doc STRUCT-OFFSET FACT) ----

/// geneve.h:90-:117 `struct GeneveHdr` field reads over the wire
/// buffer: 8 bytes, g_vl@0 g_flags@1 g_proto@2-3(BE) g_vni@4-6.
#[inline]
fn hdr_g_vl(pkt: &[u8]) -> u8 {
    pkt.first().copied().unwrap_or(0)
}
#[inline]
fn hdr_g_flags(pkt: &[u8]) -> u8 {
    *pkt.get(1).unwrap_or(&0)
}
/// geneve.h:99-:100 `hlen() { return (sizeof(GeneveHdr) + ((g_vl &
/// 0x3f) * 4)); }` — sizeof(GeneveHdr) = 8 on the C layout audit.
#[inline]
pub fn geneve_hlen(pkt: &[u8]) -> u16 {
    8 + (u16::from(hdr_g_vl(pkt) & 0x3f) * 4)
}
/// geneve.h:102-:103 `version() { return (g_vl >> 6); }`
#[inline]
pub fn geneve_version(pkt: &[u8]) -> u8 {
    hdr_g_vl(pkt) >> 6
}
/// geneve.h:105-:107 `opts_len() { return ((g_vl & 0x3f) * 4); }` —
/// uint8_t return (the C trunc face kept: max 0x3f*4 = 252 fits).
#[inline]
pub fn geneve_opts_len(pkt: &[u8]) -> u16 {
    (u16::from(hdr_g_vl(pkt) & 0x3f)) * 4
}
/// geneve.h:109-:110 `is_set(which) { return (g_flags & which); }`
#[inline]
pub fn geneve_hdr_is_set(pkt: &[u8], which: u16) -> bool {
    (u16::from(hdr_g_flags(pkt)) & which) != 0
}
/// geneve.h:112-:113 `proto() { return (ntohs(g_proto)); }` — bytes
/// 2-3 BE (the vectors:33 discriminator: probe h[4]/h[5] misses this
/// field -> next=0).
#[inline]
pub fn geneve_proto(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([*pkt.get(2).unwrap_or(&0), *pkt.get(3).unwrap_or(&0)])
}
/// geneve.h:115-:116 `vni() { return ((g_vni[0] << 16) | (g_vni[1]
/// << 8) | g_vni[2]); }` — int arithmetic in C, uint32 return.
#[inline]
pub fn geneve_vni(pkt: &[u8]) -> u32 {
    (u32::from(*pkt.get(4).unwrap_or(&0)) << 16)
        | (u32::from(*pkt.get(5).unwrap_or(&0)) << 8)
        | u32::from(*pkt.get(6).unwrap_or(&0))
}

/// geneve.h:41-:63 `struct GeneveOpt` field reads over an option
/// cursor: g_class@0-1(BE) g_type@2 g_len@3 (sizeof 4).
#[inline]
fn opt_g_type(p: &[u8]) -> u8 {
    *p.get(2).unwrap_or(&0)
}
/// geneve.h:50-:51 `is_set(which) { return (g_type & which); }`
#[inline]
pub fn geneve_opt_is_set(p: &[u8], which: u16) -> bool {
    (u16::from(opt_g_type(p)) & which) != 0
}
/// geneve.h:56-:58 `olen() { return (sizeof(GeneveOpt) + ((g_len &
/// 0x1f) * 4)); }` — uint8_t trunc kept: 4 + 31*4 = 128 wraps to 128
/// (fits u8 exactly); the C promotion walk uses the uint8 value.
#[inline]
pub fn geneve_opt_olen(p: &[u8]) -> u8 {
    (4 + u16::from(*p.get(3).unwrap_or(&0) & 0x1f) * 4) as u8
}

/// decode_data.h:108 `#define PROTO_BIT__GENEVE 0x200000` — OR at
/// cc:173. vectors:33 `bits=2097152`.
pub const PROTO_BIT__GENEVE: u32 = 0x200000;

/// snort_config.h:128 `TUNNEL_GENEVE = 0x200` — the cc:166 bypass
/// argument. DEC face mask0200 -> bypass=0 (vectors:33).
pub const TUNNEL_GENEVE: u16 = 0x200;

/// protocol_ids.h:136 `GENEVE = 0x0109` (== 265) — the
/// get_protocol_ids head (cc:86 `v.push_back` — NOTE push_back, not
/// emplace_back: no observable difference, kept as comment).
/// vectors:37 `GENPID 265 n=1`.
pub const PROTOCOL_ID_GENEVE: ProtocolId = 0x0109;

/// cc:65-:80 `class GeneveCodec : public Codec` (+ log cc:72 +
/// encode cc:73-:74 + private log_opts cc:78 + validate_options
/// cc:79).
#[derive(Default)]
pub struct GeneveCodec;

impl GeneveCodec {
    /// cc:68 `GeneveCodec() : Codec(CD_GENEVE_NAME) { }`
    pub fn new() -> GeneveCodec {
        GeneveCodec
    }

    /// cc:84-:87 `v.push_back(ProtocolId::GENEVE)` — vectors:37.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(PROTOCOL_ID_GENEVE); // cc:86
    }

    /// cc:89-:128 `bool validate_options(const uint8_t* rptr,
    /// uint16_t hdrlen, const CodecData& codec)` — the option walk +
    /// the C-flag/critical-options XOR check. C statement order kept
    /// (the hdrlen bound is compared against the WALK offset, all
    /// offsets are packet-relative — module-doc offset fact).
    pub fn validate_options(
        &self,
        pkt: &[u8],
        hdrlen: u16,
        codec: &CodecData<'_>,
        sink: QueueSink<'_>,
    ) -> bool {
        // cc:91-:96: the hdr is read off the SAME base pointer; `rptr
        // += sizeof(geneve::GeneveHdr)` starts the option cursor at
        // byte 8; `offset` counts PACKET bytes (starts at 8).
        let mut offset: u16 = 8; // cc:92 `uint16_t offset = sizeof(GeneveHdr)`
        let mut copts: u16 = 0; // cc:93

        // cc:98-:114 `while (offset < hdrlen)` per-option walk:
        while offset < hdrlen {
            let opt = &pkt[(offset as usize).min(pkt.len())..];
            let olen = u16::from(geneve_opt_olen(opt)); // cc:101
            // cc:103-:107 `if ((offset + olen) > hdrlen)` -> INVALID_
            // OPTIONS (vectors:35/:36 EV 184 + `GEN badopt -> 0`).
            if (offset + olen) > hdrlen {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_GENEVE_INVALID_OPTIONS as u32,
                    sink,
                );
                return false;
            }
            // cc:109-:110 `if (opt->is_set(GENEVE_OPT_TYPE_C)) copts++;`
            if geneve_opt_is_set(opt, GENEVE_OPT_TYPE_C) {
                copts += 1;
            }
            // cc:112-:113 the paired cursor advance:
            offset += olen;
        }

        // cc:116-:125 the C-comment truth table: C flag CLEAR +
        // critical options PRESENT, or C flag SET + critical options
        // ABSENT -> INVALID_FLAGS (vectors:31/:32 EV 183 + `GEN
        // C-no-copt -> 0`: C set, copts 0).
        if (copts == 0 && geneve_hdr_is_set(pkt, GENEVE_FLAG_C))
            || (copts != 0 && !geneve_hdr_is_set(pkt, GENEVE_FLAG_C))
        {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_GENEVE_INVALID_FLAGS as u32,
                &mut *sink,
            );
            return false;
        }
        // cc:127
        true
    }

    /// cc:130-:178 out-of-line decode (the DecodeData operand is
    /// UNNAMED at cc:130 — never read, the 18c posture). EV family
    /// all vectors-pinned: 180 (:25/:26 short), 181 (:27/:28 ver1),
    /// 182 (:29/:30 hdr-long), 183 (:31/:32 C-no-copt), 184
    /// (:35/:36 badopt, raised inside validate_options).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        bypass: &mut dyn FnMut(u16) -> bool,
        sink: QueueSink<'_>,
    ) -> bool {
        // cc:132-:136 `if (raw.len < sizeof(geneve::GeneveHdr))` ->
        // EV 180 (vectors:25/:26 `GEN short7 -> 0`; sizeof = 8).
        if raw.len < 8 {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_GENEVE_DGRAM_LT_GENEVE_HDR as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:140-:144 the version gate (vectors:27/:28 `GEN ver1 ->
        // 0`: g_vl 0x40 -> version 1 != RFC_8926_GENEVE_VERSION 0).
        if geneve_version(raw.data) != RFC_8926_GENEVE_VERSION {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_GENEVE_INVALID_VERSION as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:146-:152: opts_len read (const uint16_t in C), hdrlen
        // read (const uint32_t hlen()), raw.len < hdrlen -> EV 182
        // (vectors:29/:30 `GEN hdr-long -> 0`: g_vl 0x3f -> hdrlen
        // 260 > 8).
        let opts_len: u16 = geneve_opts_len(raw.data);
        let hdrlen: u32 = u32::from(geneve_hlen(raw.data));
        if raw.len < hdrlen {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_GENEVE_INVALID_HEADER as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:154-:159 `/* If critical header present bit is set,
        // opts_len cannot be 0 */` (the probe's C-no-copt arm has
        // opts_len 4 so this guard passes; the face below raises 183
        // inside validate_options).
        if geneve_hdr_is_set(raw.data, GENEVE_FLAG_C) && opts_len == 0 {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_GENEVE_INVALID_FLAGS as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:161-:164 `if (!validate_options(raw.data, hdrlen,
        // codec)) return false;` — the C passes the hdrlen (uint32)
        // into the uint16_t param (the trunc face kept by cast).
        if !self.validate_options(raw.data, hdrlen as u16, codec, &mut *sink) {
            return false;
        }

        // cc:166-:167 the BYPASS arm — left-open hook (module doc).
        if bypass(TUNNEL_GENEVE) {
            codec.tunnel_bypass = true;
        }

        // cc:169-:170: `uint16_t next = hdr->proto();` then the
        // GENEVE_ETH_TYPE ? ETHERNET_802_3 : (ProtocolId)next cast
        // face (module-doc offset fact: vectors:33 next=0 face).
        let next = geneve_proto(raw.data);
        let proto: ProtocolId = if next == GENEVE_ETH_TYPE {
            crate::framework::codec::protocol_id::ETHERNET_802_3
        } else {
            next // the C (ProtocolId) cast — the u16 newtype keeps it
        };

        // cc:172-:175 the write run (per-arm: lyr/bits/next/flag):
        codec.lyr_len = hdrlen as u16; // C uint32 -> uint16 trunc face
        codec.proto_bits |= PROTO_BIT__GENEVE;
        codec.next_prot_id = proto;
        codec.codec_flags |= CODEC_NON_IP_TUNNEL;

        // cc:177
        true
    }

    /// cc:180-:199 private static log_opts — NEVER vectorized (the
    /// suite never calls log; tun PLAN §6). TextLog_Print fragments
    /// reach the ordered String sink (the 18d cd_eth posture); the
    /// format strings land byte-exact (%04x/%02x -> lower-case hex,
    /// %3u -> right-aligned width 3, the leading `\n\t` kept).
    pub fn log_opts(text_log: &mut dyn FnMut(String), rptr: &[u8], opts_len: u16) {
        // offset is the OPTION-AREA cursor (rptr is already the area
        // base handed at cc:222 — offset h:182 starts 0 here, unlike
        // validate_options' packet-relative offset: the two C fns
        // differ, operand per-fn audit).
        let mut offset: usize = 0;
        while (offset as u16) < opts_len {
            let base = offset.min(rptr.len());
            let opt = &rptr[base..];
            let olen = geneve_opt_olen(opt); // h:187 == cc:187 local
            // cc:189-:190 ONE TextLog_Print fragment, format string
            // verbatim: "\n\tclass 0x%04x, type 0x%02x%s, len %3u%s"
            // (lower-case hex; %3u width-3; the rider operand is the
            // OLEN() value — always >= sizeof 4, so " value " always
            // lands; the raw g_len byte is a DIFFERENT operand, kept
            // only for the data byte count below).
            text_log(format!(
                "\n\tclass 0x{:04x}, type 0x{:02x}{}, len {:3}{}",
                u16::from_be_bytes([
                    opt.first().copied().unwrap_or(0),
                    opt.get(1).copied().unwrap_or(0),
                ]),
                opt.get(2).copied().unwrap_or(0),
                if geneve_opt_is_set(opt, GENEVE_OPT_TYPE_C) { " (C)" } else { "" },
                u16::from(olen),
                if olen != 0 { " value " } else { "" },
            ));
            // cc:192: print cursor jumps sizeof(GeneveOpt) = 4.
            let p = base + 4;
            // cc:194-:195 one "%02x " fragment PER data byte (the C
            // interleave kept: one sink call per TextLog_Print).
            let data_len = usize::from(*opt.get(3).unwrap_or(&0) & 0x1f) * 4;
            let mut idx: usize = 0;
            while idx < data_len {
                text_log(format!("{:02x} ", *rptr.get(p + idx).unwrap_or(&0)));
                idx += 1;
            }
            // cc:196-:197 the loop cursor advances by olen.
            offset += usize::from(olen);
        }
    }

    /// cc:201-:223 log — NEVER vectorized; literal port-by-reading,
    /// TextLog_Print fragments to the ordered sink.
    #[allow(clippy::needless_return)] // literal C flow kept readable
    pub fn log(
        &self,
        text_log: &mut dyn FnMut(String),
        raw_pkt: &[u8],
        _lyr_len: u16, // the C param is commented-out-name (cc:202)
    ) {
        // cc:204-:206: rptr = raw_pkt; the GeneveHdr overlay; rptr +=
        // 8 (the option cursor for log_opts).
        // cc:208-:217 the flags string build: "O" then "C", empty ->
        // "none" (String face kept).
        let mut flags = String::new();
        if geneve_hdr_is_set(raw_pkt, GENEVE_FLAG_O) {
            flags.push('O');
        }
        if geneve_hdr_is_set(raw_pkt, GENEVE_FLAG_C) {
            flags.push('C');
        }
        if flags.is_empty() {
            flags = "none".to_string();
        }
        // cc:219: `"version %u, opts_len %u flags [%s]"`
        text_log(format!(
            "version {}, opts_len {} flags [{}]",
            geneve_version(raw_pkt),
            geneve_opts_len(raw_pkt),
            flags
        ));
        // cc:220: `" network id %u, next protocol: 0x%04x"` — the
        // leading space kept byte-exact.
        text_log(format!(
            " network id {}, next protocol: 0x{:04x}",
            geneve_vni(raw_pkt),
            geneve_proto(raw_pkt)
        ));
        // cc:222 `log_opts(text_log, rptr, hdr->opts_len());` — rptr
        // past the 8-byte hdr.
        Self::log_opts(text_log, &raw_pkt[8.min(raw_pkt.len())..], geneve_opts_len(raw_pkt));
    }

    /// cc:225-:234 encode — NEVER vectorized. THE NORMAL allocate
    /// form (`!buf.allocate(...)` cc:228) — the contrast that makes
    /// the gtp inversion an upstream oddity, not a house style.
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        _enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // cc:228-:229 the NORMAL gate:
        if !buf.allocate(u32::from(raw_len)) {
            return false;
        }
        // cc:231-:232 the GeneveHdr overlay + memcpy(hdr, raw_in,
        // raw_len) over the allocated face (landed Buffer data_off
        // face, the 18d Buffer face).
        if let Some(d) = buf.data_mut() {
            // cc:232 memcpy(hdr, raw_in, raw_len): allocate() grows
            // the live window so the FIRST raw_len bytes of the
            // data() face are the newly reserved area (the landed
            // 18c Buffer base/end bookkeeping).
            let n = usize::from(raw_len).min(d.len());
            d[..n].copy_from_slice(&raw_in[..n]);
        }
        // cc:233
        true
    }
}

// ---- THE GeneveLyr face (geneve.h:119-:147) — row-scoped landing,
// module doc; the misc/test up_geneve_* suites arm get_opt_data
// directly ----

/// geneve.h:29 `#define MAX_OPT_DATA_LEN 124` (`(((2 ^ 5) - 1) * 4)`
/// per the :28 comment).
pub const MAX_OPT_DATA_LEN: usize = 124;

/// geneve.h:41-:63 `struct GeneveOpt` as a value type (the four wire
/// bytes; accessors re-derived from the raw slots so olen/data_len
/// keep the C bit-math).
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct GeneveOptVal {
    pub g_class: [u8; 2], // uint16_t wire slot
    pub g_type: u8,
    pub g_len: u8,
}

impl GeneveOptVal {
    /// geneve.h:47-:48 `optclass() { return ntohs(g_class); }`
    pub fn optclass(&self) -> u16 {
        u16::from_be_bytes(self.g_class)
    }
    /// geneve.h:50-:51 is_set over g_type
    pub fn is_set(&self, which: u16) -> bool {
        (u16::from(self.g_type) & which) != 0
    }
    /// geneve.h:53-:54 `type() { return g_type; }`
    pub fn type_(&self) -> u8 {
        self.g_type
    }
    /// geneve.h:56-:58 olen (uint8_t trunc kept)
    pub fn olen(&self) -> u8 {
        (4 + u16::from(self.g_len & 0x1f) * 4) as u8
    }
    /// geneve.h:60-:62 `data_len() { return ((g_len & 0x1f) * 4); }`
    pub fn data_len(&self) -> u8 {
        (u16::from(self.g_len & 0x1f) * 4) as u8
    }
}

/// geneve.h:65-:76 `struct GeneveOptData` — opt copy + the data[124]
/// face; the Rust stand-in owns a Vec (the fixed-array fold,
/// deviations). The C ctor asserts `len <= MAX_OPT_DATA_LEN` (h:69):
/// kept as a debug_assert.
#[derive(Clone, Debug, PartialEq)]
pub struct GeneveOptData {
    pub opt: GeneveOptVal,
    pub data: Vec<u8>,
}

/// geneve.h:119-:147 `struct GeneveLyr { GeneveHdr hdr; uint8_t
/// data[256]; get_opt_data(); } __attribute__((packed))` — the Rust
/// face is a fn over the full packet slice (hdr bytes 0-8, option
/// area from byte 8 — the packed layout audit: data starts at 8).
/// The walk is the SAME shape as validate_options BUT terminates on
/// a bad olen with `break` (h:136-:137 `break; // Invalid opt
/// length.`) — NO event (the C difference kept: validate_options
/// events, get_opt_data breaks).
pub fn geneve_get_opt_data(pkt: &[u8]) -> Vec<GeneveOptData> {
    let mut options: Vec<GeneveOptData> = Vec::new();
    let all_opt_len = geneve_opts_len(pkt); // h:127 hdr.opts_len()
    let mut offset: u16 = 0; // h:128 — the cursor into the DATA area
    let data = &pkt[8.min(pkt.len())..];
    let mut dptr: u16 = 0;
    // h:131-:143 `while (offset < all_opt_len)` walk:
    while offset < all_opt_len {
        let opt_bytes = &data[(dptr as usize).min(data.len())..];
        let opt = GeneveOptVal {
            g_class: [opt_bytes.first().copied().unwrap_or(0), opt_bytes.get(1).copied().unwrap_or(0)],
            g_type: opt_bytes.get(2).copied().unwrap_or(0),
            g_len: opt_bytes.get(3).copied().unwrap_or(0),
        };
        let olen = u16::from(opt.olen());
        // h:136-:137 the BREAK face (event-free, unlike validate_options):
        if (offset + olen) > all_opt_len {
            break;
        }
        // h:139 `options.emplace_back(opt, dptr + sizeof(GeneveOpt),
        // opt->data_len());`
        let n = usize::from(opt.data_len());
        debug_assert!(n <= MAX_OPT_DATA_LEN, "geneve.h:69 C assert");
        let start = (dptr as usize + 4).min(data.len());
        options.push(GeneveOptData {
            opt,
            data: data[start..(start + n).min(data.len())].to_vec(),
        });
        dptr += olen;
        offset += olen;
    }
    options
}

// cc:240-:241 `static Module* mod_ctor() { return new GeneveModule;
// }` + cc:243-:244 mod_dtor — presence pair TRUE on the record; the
// Rust mod_ctor() face is GeneveModule::new. cc:246-:250 the codec
// ctor/dtor pair.

/// cc:252-:272 `static const CodecApi geneve_api` — vectors:1 `API
/// geneve type=0 size=112 ver=1900547 name=geneve` + vectors:2 HELP +
/// the mod pair cc:263-:264 SET.
pub const GENEVE_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:255
    size: CDAPI_SIZEOF_CODEC_API, // cc:256
    api_version: CDAPI_VERSION,   // cc:257
    version: 0,                   // cc:258
    features: PLUGIN_SO_RELOAD,   // cc:259
    options: API_OPTIONS,         // cc:260
    name: CD_GENEVE_NAME,         // cc:261
    help: CD_GENEVE_HELP,         // cc:262
    mod_ctor: true,               // cc:263 SET
    mod_dtor: true,               // cc:264 SET
    pinit: false,                 // cc:266
    pterm: false,                 // cc:267
    tinit: false,                 // cc:268
    tterm: false,                 // cc:269
    ctor: true,                   // cc:270
    dtor: true,                   // cc:271
};

/// cc:274-:282 the `cd_geneve[]` table (non-SO face; STATIC_CODEC_
/// EXTERN_NAMES :109 already resident — never re-touched).
pub const CD_GENEVE: CodecTable = &[&GENEVE_API];
