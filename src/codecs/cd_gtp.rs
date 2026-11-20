//! Port of `src/codecs/misc/cd_gtp.cc` (291 L) — row 18f.
//! Ground: snort3-src @ fe29cbe, md5 `d0719e95a9ddc985ae09c4ba853bf17a`
//! (tun PLAN §0). DIR FACT: `codecs/misc/`. TRUE NAME: `cd_gtp` at
//! cc:285 (BUILDING_SO ternary face :282-:290) — file base == extern
//! name (no hop_opts-style drift on this row; tun PLAN §0).
//!
//! MODULE PAIR: GtpModule : BaseCodecModule (cc:43-:50) + the 2-row
//! `gtp_rules` RuleMap (cc:36-:41) — vectors:39 `GTP rules=2 sid0=297
//! name=gtp` (the `while (sid) n++` walk over { MULTIPLE_ENCAPSULATION
//! 297 codec_module.h:151, BAD_LEN 298 h:152, {0,nullptr} } +
//! get_name) + vectors_faceA.txt:6 `API gtp mod_ctor=1`. RuleMap /
//! rule_count / BaseCodecModule / CodecSid ride the landed 18d homes
//! (reused, never re-forked).
//!
//! THE BYPASS HOOK — LEFT-OPEN (tun PLAN §4/§7, named in deviations
//! row 18f): cc:177 `codec.conf->tunnel_bypass_enabled(TUNNEL_GTP)`
//! (ground def main/snort_config.cc:1020-:1023) lands as an explicit
//! hook param `&mut dyn FnMut(u16) -> bool` — the same ruling as
//! cd_teredo.rs; tunnel_mask (snort_config.h:393 NSDMI 0) and the
//! SFDAQ arm (DAQ = plan row 20) stay queued config/DAQ rows.
//!
//! DECODE-FLAGS SEAM (the 18e IpApiLite precedent, left-open):
//! cc:183-:186 read-and-write the DecodeData operand's decode_flags
//! DECODE_GTP bit (decode_data.h:149 `DECODE_GTP = 0x00001000`) — the
//! multiple-encapsulation latch. This row lands the minimal
//! read-write seam `GtpDecodeFlags` below; the layer that owns the
//! real DecodeData flag word stays OPEN for the parser/decode rows.
//!
//! UPSTREAM ODDITIES (literal, NEVER "fixed"; deviations row 18f):
//! (1) encode INVERSION: cc:228-:229 `if (buf.allocate(raw_len))
//! return false;` — the ALLOCATE-SUCCESS path returns false, the
//! opposite of cd_eth cc:157-:158 and cd_geneve cc:228-:229. (2)
//! update_GTP_length (cc:207-:223) can NEVER return true: cases 0/1
//! write the length field and fall to the shared `return false;`
//! (cc:222); default returns false early (cc:219-:220). The gtp
//! encode/update pair is therefore permanently false at the Codec
//! API boundary in ground — pin only the observable side effects.
//! (3) the v1 extension-walk `len` does NOT feed the final length
//! gate (cc:166 compares against the FROZEN GTP_MIN_LEN, not len —
//! operand identity per arm).
//!
//! encode/update are NEVER vectorized (tun PLAN §6 probe arms:
//! decode/pid/rules/API faces only) — literal port-by-reading, every
//! move cited; the misc/test/gtp_codec_test.cc TESTs (:93/:116) arm
//! DECODE only (the OOB-inner-read regression guard).
//!
//! ROW-SCOPED VOCAB (15-path staging; deviations row 18f): the
//! protocol_ids.h / decode_data.h / snort_config.h numerics this TU
//! touches land HERE with the C cites (framework/codec.rs and
//! parse_conf.rs byte-UNTOUCHED this row — the 18e posture).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CodecApiRecord, CodecTable, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    CODEC_ENCAP_LAYER, CODEC_NON_IP_TUNNEL, CodecData, EncState, EncodeFlags, PLUGIN_SO_RELOAD,
    PT_CODEC, ProtocolId, RawData,
};

/// cc:31 `#define CD_GTP_NAME "gtp"`
pub const CD_GTP_NAME: &str = "gtp";
/// cc:32 `#define CD_GTP_HELP "support for general-packet-radio-service
/// tunneling protocol"` — vectors:4 HELP face (full words kept).
pub const CD_GTP_HELP: &str = "support for general-packet-radio-service tunneling protocol";

/// cc:36-:41 `static const RuleMap gtp_rules[]` — the 2-row table +
/// the `{ 0, nullptr }` terminator (18d RuleMap posture; vectors:39
/// `GTP rules=2 sid0=297 name=gtp`).
pub const GTP_RULES: [RuleMap; 3] = [
    RuleMap {
        sid: CodecSid::DECODE_GTP_MULTIPLE_ENCAPSULATION as u32, // 297 (codec_module.h:151, landed 18d)
        msg: Some("two or more GTP encapsulation layers present"), // cc:38 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GTP_BAD_LEN as u32, // 298 (h:152)
        msg: Some("GTP header length is invalid"), // cc:39 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:40 terminator
];

/// cc:43-:50 `class GtpModule : public BaseCodecModule` — get_rules()
/// override cc:48-:49 returns the table head.
#[derive(Debug)]
pub struct GtpModule {
    pub base: BaseCodecModule,
}

impl GtpModule {
    /// cc:46 `GtpModule() : BaseCodecModule(CD_GTP_NAME, CD_GTP_HELP) { }`
    pub fn new() -> GtpModule {
        GtpModule {
            base: BaseCodecModule::new(CD_GTP_NAME, CD_GTP_HELP),
        }
    }

    /// cc:48-:49 `{ return gtp_rules; }` — the rule_count walker is
    /// the landed 18d home (vectors:39 `rules=2`).
    pub fn get_rules() -> &'static [RuleMap] {
        &GTP_RULES
    }

    /// vectors:39 `name=gtp` (Module::get_name over the cc:46 slot;
    /// GID/Usage faces ride the landed BaseCodecModule).
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for GtpModule {
    fn default() -> Self {
        Self::new()
    }
}

// cc:69-:74 `struct GTPHdr { uint8_t flag; uint8_t type; uint16_t
// length; }` — wire layout: flag @0, PDU-type byte @1, length (net
// order) @2-3. The Rust port reads the overlay through indexed
// reads (the cd_eth ethertype posture, LE-host net reads), NOT a
// #[repr(C)] pun — deviations records the fold (layout-charge
// counters are a later row).

/// cc:77 `static const uint32_t GTP_MIN_LEN = 8;`
pub const GTP_MIN_LEN: u32 = 8;
/// cc:78 `static const uint32_t GTP_V0_HEADER_LEN = 20;`
pub const GTP_V0_HEADER_LEN: u32 = 20;
/// cc:79 `static const uint32_t GTP_V1_HEADER_LEN = 12;`
pub const GTP_V1_HEADER_LEN: u32 = 12;

/// decode_data.h:149 `DECODE_GTP = 0x00001000` — the DecodeData
/// decode_flags latch bit touched at cc:183/:186.
pub const DECODE_GTP: u64 = 0x00001000;

/// THE decode-flags seam (module doc): the read-write stand-in for
/// the DecodeData::decode_flags bit of cc:183-:186 — NOT a DecodeData
/// port; the owning layer stays open. C fresh-DecodeData face =
/// decode_flags 0 (probe_dec DecodeData gd*; suite fixture same).
#[derive(Copy, Clone, Default)]
pub struct GtpDecodeFlags {
    pub decode_flags: u64, // cc:183 `dd.decode_flags & DECODE_GTP` / cc:186 `|=`
}

/// decode_data.h:95 `#define PROTO_BIT__GTP 0x000100` — OR at cc:181.
/// vectors:18 `bits=256`.
pub const PROTO_BIT__GTP: u32 = 0x000100;

/// snort_config.h:119 `TUNNEL_GTP = 0x01` (enum TunnelFlags) — the
/// cc:177 bypass argument. DEC face: mask0001 -> bypass=0
/// (vectors:18).
pub const TUNNEL_GTP: u16 = 0x01;

/// protocol_ids.h:129 `GTP = 0x0102` (== 258) — the get_protocol_ids
/// head (cc:83). vectors:24 `GTPPID 258 n=1`.
pub const PROTOCOL_ID_GTP: ProtocolId = 0x0102;

/// cc:56-:67 `class GtpCodec : public Codec` (decode cc:62 + encode
/// cc:63-:64 + update cc:65-:66).
#[derive(Default)]
pub struct GtpCodec;

impl GtpCodec {
    /// cc:59 `GtpCodec() : Codec(CD_GTP_NAME) { }`
    pub fn new() -> GtpCodec {
        GtpCodec
    }

    /// cc:81-:84 `v.emplace_back(ProtocolId::GTP)` — vectors:24.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(PROTOCOL_ID_GTP); // cc:83
    }

    /// cc:86-:201 out-of-line decode, statement order VERBATIM. The
    /// vectors-pinned EV face: `EV 116 298` x2 (v0-shord vectors:16 +
    /// v1-badlen vectors:21 — the build.sh MEASURED double-count) and
    /// `EV 116 297` (v1-twice vectors:19 — the event NEVER flips the
    /// return, vectors:20 `-> 1`).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        dd: &mut GtpDecodeFlags,
        bypass: &mut dyn FnMut(u16) -> bool,
        sink: crate::framework::codec::QueueSink<'_>,
    ) -> bool {
        // cc:91 the GTPHdr overlay (reads below carry the offsets).
        // cc:93-:94 `if (raw.len < GTP_MIN_LEN) return false;` —
        // vectors:13 `GTP short7 -> 0` (NO event on this arm).
        if raw.len < GTP_MIN_LEN {
            return false;
        }

        // cc:95-:97 `/* We only care about PDU*/ if (hdr->type != 255)
        // return false;` — vectors:14 `GTP type1 -> 0`.
        if *raw.data.get(1).unwrap_or(&0) != 255 {
            return false;
        }

        // cc:98-:100 `/*Check whether this is GTP or GTP', Exit if
        // GTP'*/ if (!(hdr->flag & 0x10)) return false;` — vectors:15
        // `GTP gtpprime -> 0` (flag 0x20: the PT bit reads clear).
        let flag = raw.data.first().copied().unwrap_or(0);
        if (flag & 0x10) == 0 {
            return false;
        }

        // cc:102-:104 `/*The first 3 bits are version number*/ version
        // = (hdr->flag & 0xE0) >> 5; switch (version)`.
        let version = (flag & 0xE0) >> 5;
        let len: u32;
        match version {
            0 => {
                // cc:106-:120 GTP v0.
                len = GTP_V0_HEADER_LEN; // cc:107
                // cc:108-:112 short face -> EV 298 + false: vectors:16
                // `EV 116 298` + :17 `GTP v0-shord -> 0` (raw 8 < 20).
                if raw.len < len {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_GTP_BAD_LEN as u32,
                        &mut *sink,
                    );
                    return false;
                }
                // cc:114-:118 the exact-length gate: `raw.len !=
                // ((unsigned int)ntohs(hdr->length) + len)` (the
                // unsigned-int cast kept — u32). Same EV + false.
                let length_field = u32::from(u16::from_be_bytes([
                    *raw.data.get(2).unwrap_or(&0),
                    *raw.data.get(3).unwrap_or(&0),
                ]));
                if raw.len != (length_field + len) {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_GTP_BAD_LEN as u32,
                        &mut *sink,
                    );
                    return false;
                }
            }
            1 => {
                // cc:121-:171 GTP v1: the optional bits pick the base
                // len; the extension chain then walks raw bytes.
                let mut len_v: u32;
                // cc:123 `if (hdr->flag & 0x07)` — S|PN|E bits.
                if flag & 0x07 != 0 {
                    len_v = GTP_V1_HEADER_LEN; // cc:125
                    // cc:128-:132 `if (raw.len < GTP_V1_HEADER_LEN)`
                    // -> EV + false, BEFORE the byte read at cc:133
                    // (C statement order kept).
                    if raw.len < GTP_V1_HEADER_LEN {
                        crate::framework::codec::codec_event(
                            codec,
                            CodecSid::DECODE_GTP_BAD_LEN as u32,
                            &mut *sink,
                        );
                        return false;
                    }
                    // cc:133 `uint8_t next_hdr_type = *(raw.data + len
                    // - 1);` — index 11 (the probe never arms this
                    // face; the get posture stands where C overruns).
                    let mut next_hdr_type = *raw.data.get((len_v - 1) as usize).unwrap_or(&0);
                    // cc:136-:161 `while (next_hdr_type)` extension
                    // walk — four BAD_LEN guards in C order:
                    while next_hdr_type != 0 {
                        // cc:139-:143 `if (raw.len < len + 4)`
                        if raw.len < len_v + 4 {
                            crate::framework::codec::codec_event(
                                codec,
                                CodecSid::DECODE_GTP_BAD_LEN as u32,
                                &mut *sink,
                            );
                            return false;
                        }
                        // cc:145 `ext_hdr_len = *(raw.data + len);`
                        let ext_hdr_len = *raw.data.get(len_v as usize).unwrap_or(&0);
                        // cc:147-:151 `if (!ext_hdr_len)`
                        if ext_hdr_len == 0 {
                            crate::framework::codec::codec_event(
                                codec,
                                CodecSid::DECODE_GTP_BAD_LEN as u32,
                                &mut *sink,
                            );
                            return false;
                        }
                        // cc:152-:153 `/*Extension header length is a
                        // unit of 4 octets*/ len += ext_hdr_len * 4;`
                        len_v += u32::from(ext_hdr_len) * 4;
                        // cc:155-:159 `if (raw.len < len)`
                        if raw.len < len_v {
                            crate::framework::codec::codec_event(
                                codec,
                                CodecSid::DECODE_GTP_BAD_LEN as u32,
                                &mut *sink,
                            );
                            return false;
                        }
                        // cc:160 `next_hdr_type = *(raw.data + len - 1);`
                        next_hdr_type = *raw.data.get((len_v - 1) as usize).unwrap_or(&0);
                    }
                } else {
                    // cc:163-:164 `else len = GTP_MIN_LEN;`
                    len_v = GTP_MIN_LEN;
                }
                // cc:166-:170 the v1 length gate on the FROZEN
                // GTP_MIN_LEN (NOT len — the extension-walk len does
                // NOT feed this comparison, oddity (3)): vectors:21
                // `EV 116 298` + :22 `GTP v1-badlen -> 0` (length 5:
                // 8 != 5+8).
                let length_field = u32::from(u16::from_be_bytes([
                    *raw.data.get(2).unwrap_or(&0),
                    *raw.data.get(3).unwrap_or(&0),
                ]));
                if raw.len != (length_field + GTP_MIN_LEN) {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_GTP_BAD_LEN as u32,
                        &mut *sink,
                    );
                    return false;
                }
                len = len_v;
            }
            // cc:173-:174 `default: return false;`
            _ => return false,
        }

        // cc:177-:178 the BYPASS arm — left-open hook (module doc).
        if bypass(TUNNEL_GTP) {
            codec.tunnel_bypass = true;
        }

        // cc:180-:181 lyr_len = len (C uint32 -> uint16 field, the
        // trunc face kept by cast) + the GTP bits OR.
        codec.lyr_len = len as u16;
        codec.proto_bits |= PROTO_BIT__GTP;

        // cc:183-:186 the multi-encapsulation latch: bit already set
        // -> EV 297 (vectors:19 `EV 116 297` + :20 `GTP v1-twice ->
        // 1` — never returns false); else OR the bit in.
        if dd.decode_flags & DECODE_GTP != 0 {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_GTP_MULTIPLE_ENCAPSULATION as u32,
                &mut *sink,
            );
        } else {
            dd.decode_flags |= DECODE_GTP; // cc:186
        }

        // cc:188-:197 the inner-layer arm: `if (raw.len > len)` gates
        // the version-nibble read at raw.data + len — the EXACTLY-
        // fills guard the gtp_codec_test.cc:212-:214 comment pins as
        // the upstream OOB-read regression. vectors:23 `GTP v1-encap
        // -> 1 next=4 lyr=8 flags=518` (0x45 nibble -> IPIP; 518 =
        // 0x206 = ENCAP | NON_IP_TUNNEL).
        if raw.len > len {
            codec.codec_flags |= CODEC_ENCAP_LAYER; // cc:190
            let ip_ver = *raw.data.get(len as usize).unwrap_or(&0) & 0xF0; // cc:191
            if ip_ver == 0x40 {
                codec.next_prot_id = crate::framework::codec::protocol_id::IPIP; // cc:194 (4)
            } else if ip_ver == 0x60 {
                codec.next_prot_id = crate::framework::codec::protocol_id::IPV6; // cc:196 (41)
            }
            // cc:193/:195 the neither face keeps next_prot_id at the
            // init value (no else arm — literal).
        }
        // cc:198
        codec.codec_flags |= CODEC_NON_IP_TUNNEL;
        // cc:200
        true
    }

    /// cc:225-:234 encode. NEVER vectorized — literal port-by-
    /// reading. THE UPSTREAM INVERSION (oddity (1), module doc):
    /// cc:228-:229 `if ( buf.allocate(raw_len) ) return false;` — the
    /// allocate-success path returns false (cd_eth/cc_geneve carry
    /// the `!` form). On the allocate-FAILURE path C memcpy's raw_len
    /// bytes through the stale buffer face and calls
    /// update_GTP_length (the never-vectorized dead-continuation UB
    /// face): the port models the defined bounded copy over the
    /// current data face and records the substitution in deviations
    /// (skill UB rule — never replicate the overrun). The Buffer
    //  operand is the landed 18c Buffer; the Flow* operand is
    //  UNNAMED in C (cc:64) — the never-read posture.
    #[allow(clippy::needless_return)] // literal C flow kept readable
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        _enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // cc:228-:229 the inverted gate kept EXACT:
        if buf.allocate(u32::from(raw_len)) {
            return false;
        }
        // cc:231 the GTPHdr overlay + cc:232 memcpy(gtph, raw_in,
        // raw_len) over the FAILED-allocate face, then cc:233
        // `return update_GTP_length(gtph, buf.size());` — always
        // false through that helper (oddity (2)) whatever the copy
        // face does.
        let size = buf.size(); // buf.size() BEFORE any further mutation, the cc:233 arg
        if let Some(d) = buf.data_mut() {
            let n = usize::from(raw_len).min(d.len());
            d[..n].copy_from_slice(&raw_in[..n]);
            // cc:233 (the helper's bool is returned verbatim):
            return Self::update_gtp_length(d, size);
        }
        // zero-size Buffer face (data() INVALID in C): the defined
        // false stand-in (deviations UB substitution).
        false
    }

    /// cc:236-:242 update: `updated_len += lyr_len;
    /// update_GTP_length(h, updated_len);` — the uint32 accumulate
    /// kept wrapping (skill: every C counter arithmetic literal);
    /// the helper's never-true bool is DROPPED by the void caller
    /// (cc:241). NEVER vectorized.
    pub fn update(
        &self,
        _api: &(),
        _flags: EncodeFlags,
        raw_pkt: &mut [u8],
        lyr_len: u16,
        updated_len: &mut u32,
    ) {
        // cc:240 (`updated_len += lyr_len` — the C reference param):
        *updated_len = updated_len.wrapping_add(u32::from(lyr_len));
        // cc:239 the GTPHdr overlay + cc:241 the helper over the raw
        // buffer (length field @2-3, net order).
        Self::update_gtp_length(raw_pkt, *updated_len);
    }

    /// cc:207-:223 `static inline bool update_GTP_length(GTPHdr*
    /// const gtph, int gtp_total_len)` — THE NEVER-TRUE helper
    /// (oddity (2)): cases 0/1 write `gtph->length = htons(total -
    /// base)` (the C `int` slot + `(uint16_t)` cast kept as wrapping
    /// u32 -> u16 trunc — the probe/suite faces are far from the
    /// wrap) then fall to the shared `return false;` at cc:222;
    /// default `return false;` cc:219-:220 writes nothing. The
    /// slice face is the buffer/raw_pkt overlay (length @2-3).
    #[allow(clippy::needless_return)] // literal C shared tail kept readable
    fn update_gtp_length(hdr: &mut [u8], gtp_total_len: u32) -> bool {
        // cc:209-:210 `const uint8_t version = (gtph->flag & 0xE0) >> 5;`
        let version = (hdr.first().copied().unwrap_or(0) & 0xE0) >> 5;
        let value: u16 = match version {
            // cc:213-:215 v0: `gtph->length = htons((uint16_t)(len -
            // GTP_V0_HEADER_LEN));` then FALL THROUGH to cc:222.
            0 => gtp_total_len.wrapping_sub(GTP_V0_HEADER_LEN) as u16,
            // cc:216-:218 v1: the same over GTP_MIN_LEN, also falls:
            1 => gtp_total_len.wrapping_sub(GTP_MIN_LEN) as u16,
            // cc:219-:220 `default: return false;` (no write):
            _ => return false,
        };
        // cc:214/:217 the net-order field write (C uint16_t member
        // overlay @2-3). A short overlay buffer is the never-armed UB
        // face: the defined bounded stand-in (deviations).
        if hdr.len() >= 4 {
            hdr[2..4].copy_from_slice(&value.to_be_bytes());
        }
        // cc:222 the shared `return false;` — cases 0/1 STILL return
        // false after the write (oddity (2) verbatim).
        false
    }
}

// cc:248-:249 `static Module* mod_ctor() { return new GtpModule; }` +
// cc:251-:252 mod_dtor — presence pair TRUE on the record
// (vectors_faceA:6 `API gtp mod_ctor=1`); the Rust mod_ctor() face is
// GtpModule::new (stack-owned drop, 18d posture). cc:254-:258 the
// codec ctor/dtor pair.

/// cc:260-:280 `static const CodecApi gtp_api` — vectors:3 `API gtp
/// type=0 size=112 ver=1900547 name=gtp` + vectors:4 HELP + the mod
/// pair cc:271-:272 SET (the trio contrast vs the teredo nullptr arm).
pub const GTP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:263
    size: CDAPI_SIZEOF_CODEC_API, // cc:264 sizeof(CodecApi)=112
    api_version: CDAPI_VERSION,   // cc:265 1900547
    version: 0,                   // cc:266
    features: PLUGIN_SO_RELOAD,   // cc:267
    options: API_OPTIONS,         // cc:268
    name: CD_GTP_NAME,            // cc:269
    help: CD_GTP_HELP,            // cc:270
    mod_ctor: true,               // cc:271 SET
    mod_dtor: true,               // cc:272 SET
    pinit: false,                 // cc:274
    pterm: false,                 // cc:275
    tinit: false,                 // cc:276
    tterm: false,                 // cc:277
    ctor: true,                   // cc:278
    dtor: true,                   // cc:279
};

/// cc:282-:290 the `cd_gtp[]` table (non-SO face; the name already
/// resident in codec_api.rs STATIC_CODEC_EXTERN_NAMES :111 — never
/// re-touched).
pub const CD_GTP: CodecTable = &[&GTP_API];
