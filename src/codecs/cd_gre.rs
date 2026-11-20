//! Port of `src/codecs/ip/cd_gre.cc` (366 L) — row 18g, THE gate-change row.
//! Ground: snort3-src @ fe29cbe, md5 `361de6ff6f7a75b10e040729875f9ba5`
//! (gre build.sh :40, re-run EVERY build). DIR FACT: `codecs/ip/`.
//!
//! TRUE-NAME FACT (gre PLAN §0/§3): file base == extern table name —
//! `cd_gre` at cc:340 (the BUILDING_SO ternary face :337-:341 with the
//! REAL live arms, contrast the 18e commented hopopts face), NO
//! cd_hop_opts-style drift tripwire (grep-asserted at ground build.sh
//! :51-:53).
//!
//! THE GATE (gre PLAN §4 — FIRST real codec Catch gate in the lineage):
//! the ground embedded block :351-:366 carries exactly ONE TEST_CASE
//! ("Validate error check for raw_len greater than GRE_HEADER_LEN",
//! "[cd_gre]") with ONE CHECK at :364 (whole-file CHECK grep = 1,
//! build.sh :48). The harness gate runs the GROUND block VERBATIM under
//! the shim route (shim-route deviation, KNOWN DEVIATIONS row 18g):
//! runner tail "All tests passed (1 assertion in 1 test case)",
//! gate.txt md5 `6751d1a8c21da0fdfed87ddfd4d37c5f` TRACKED — the new
//! chain anchor (first break after 14 straight byte-ident 4826fc22
//! rows; the 9 legacy holders stay byte-frozen, two md5 lineages from
//! this row on, census MEASURED by the loop at build.sh :401-:403).
//! The Rust twin of the case lands statement-for-statement in
//! tests/gre_parity_test.rs as `up_gate_*` (the 18b translated shape —
//! the C side is NOT translated-not-run here: the gate actually RUNS).
//!
//! THE BYPASS HOOK — LEFT-OPEN RULING (gre PLAN §7, extended from the
//! 18e IpApiLite / 18f tunnel-trio ruling): cc:280
//! `codec.conf->tunnel_bypass_enabled(TUNNEL_GRE)` is the ground conf
//! read; the production provider (SnortConfig field + SFDAQ arm, DAQ =
//! plan row 20) stays OPEN. The call site lands as a hook parameter
//! `&mut dyn FnMut(u16) -> bool`; the parity replay's hook mirrors
//! tools/tun_harness/witness_18f.cc byte-exactly (observable table
//! tun_mask + ground-shaped return `!((mask & proto) or daq)`, daq arm
//! pinned false). GRE rides the SAME witness table from 18f — ZERO new
//! witnesses this row; TUNNEL_GRE 0x40 pinned from snort_config.h:125
//! (build.sh :74), NEVER typed.
//!
//! CHECKSUM CONSUMER (the 18b cross-row face): cc:122/:160 call
//! `checksum::cksum_add` — the FIRST C-side consumer of the 284-L
//! header any donor tree ever cp'd (gre build.sh :116-:123, csum.h
//! md5 b43628f3 pinned); the Rust row reuses the landed
//! `crate::codecs::checksum::cksum_add` (row 18b) — the C probe faces
//! `UPD chksum-bytes 127 255` / `ENC ok ... 103 255` (vectors:26 /
//! :24) re-produced EXACTLY by the Rust fn (deviations row 18g).
//!
//! ROW-SCOPED VOCAB (deviations row 18g: 14-path staging): the protocol_ids.h /
//! decode_data.h / snort_config.h / codec_module.h numerics this TU
//! touches land HERE with the C cites (framework/codec.rs and
//! parse_conf.rs byte-UNTOUCHED this row — 18e/18f posture; the
//! tunnel_mask config-row homes stay QUEUED).
//!
//! ZERO-DECODE-DATA FACT: the C `DecodeData&` parameter is UNNAMED
//! (cc:167) and never read — the decode signature therefore carries no
//! ports seam (contrast the 18f TeredoPorts). sids: all six
//! DECODE_GRE_* ALREADY landed codec_module.rs:107-:112 (h:93-:98);
//! the row adds ZERO new constants (build.sh :62-:67 census).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CodecApiRecord, CodecTable, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    CODEC_ETHER_NEXT, CODEC_NON_IP_TUNNEL, CodecData, EncState, EncodeFlags, PLUGIN_SO_RELOAD,
    PT_CODEC, ProtocolId, QueueSink, RawData, ip_protocol, protocol_id,
};

/// cc:40 `#define CD_GRE_NAME "gre"`
pub const CD_GRE_NAME: &str = "gre";
/// cc:41 `#define CD_GRE_HELP "support for generic routing encapsulation"`
/// — vectors:2 + vectors_faceA:4 face (build.sh :325 sed-pins the define).
pub const CD_GRE_HELP: &str = "support for generic routing encapsulation";

/// cc:79 `static const uint32_t GRE_HEADER_LEN = 4;` — the TEST_CASE's
/// SUBJECT constant (build.sh :333 pins the line verbatim).
pub const GRE_HEADER_LEN: u32 = 4;
/// cc:80 `GRE_CHKSUM_LEN = 2`
pub const GRE_CHKSUM_LEN: u32 = 2;
/// cc:81 `GRE_OFFSET_LEN = 2`
pub const GRE_OFFSET_LEN: u32 = 2;
/// cc:82 `GRE_KEY_LEN = 4`
pub const GRE_KEY_LEN: u32 = 4;
/// cc:83 `GRE_SEQ_LEN = 4`
pub const GRE_SEQ_LEN: u32 = 4;
/// cc:84 `GRE_SRE_HEADER_LEN = 4`
pub const GRE_SRE_HEADER_LEN: u32 = 4;
/// cc:88 `GRE_V1_ACK_LEN = 4` (the cc:86-:87 GRE_V1_HEADER_LEN comment
/// block is dead in C — nothing lands, kept as a doc pin).
pub const GRE_V1_ACK_LEN: u32 = 4;

/// protocol_ids.h:152 `ETHERTYPE_PPP = 0x880B` (== 34827) — the v1
/// protocol guard (cc:246) and the vectors:19 next=34827 face.
/// ROW-SCOPED home (18e/18f posture: framework/codec.rs byte-UNTOUCHED
/// this row; the teredo PROTOCOL_ID_TEREDO precedent).
pub const PROTOCOL_ID_ETHERTYPE_PPP: ProtocolId = 0x880B;

/// snort_config.h:125 `TUNNEL_GRE = 0x40` (enum TunnelFlags :119-:128 —
/// build.sh :74 sed-pins the line) — the argument of the cc:280 bypass
/// call. DEC face: mask0040 -> bypass=0 / mask0000 -> bypass=1
/// (vectors:19/:20).
pub const TUNNEL_GRE: u16 = 0x40;

// ---- the cc:90-:98 flag macros as small fns over the gre.h field face ----
/// cc:90 `GRE_V1_FLAGS(x) ((x)->version & 0x78)`
#[inline]
pub fn gre_v1_flags(version: u8) -> u8 {
    version & 0x78
}
/// cc:91 `GRE_V1_ACK(x) ((x)->version & 0x80)`
#[inline]
pub fn gre_v1_ack(version: u8) -> u8 {
    version & 0x80
}
/// cc:92 `GRE_CHKSUM(x) ((x)->flags & 0x80)`
#[inline]
pub fn gre_chksum(flags: u8) -> u8 {
    flags & 0x80
}
/// cc:93 `GRE_ROUTE(x) ((x)->flags & 0x40)`
#[inline]
pub fn gre_route(flags: u8) -> u8 {
    flags & 0x40
}
/// cc:94 `GRE_KEY(x) ((x)->flags & 0x20)`
#[inline]
pub fn gre_key(flags: u8) -> u8 {
    flags & 0x20
}
/// cc:95 `GRE_SEQ(x) ((x)->flags & 0x10)`
#[inline]
pub fn gre_seq(flags: u8) -> u8 {
    flags & 0x10
}
/// cc:96 `GRE_SSR(x) ((x)->flags & 0x08)`
#[inline]
pub fn gre_ssr(flags: u8) -> u8 {
    flags & 0x08
}
/// cc:97 `GRE_RECUR(x) ((x)->flags & 0x07)`
#[inline]
pub fn gre_recur(flags: u8) -> u8 {
    flags & 0x07
}
/// cc:98 `GRE_FLAGS(x) ((x)->version & 0xF8)`
#[inline]
pub fn gre_flags(version: u8) -> u8 {
    version & 0xF8
}

// ---- protocols/gre.h:30-:46 GREHdr field face (byte-slice overlay
// reads; gre.h md5 7b07af8e = the fresh cp pinned at build.sh :109-:110) ----

/// gre.h:32 `uint8_t flags` — byte 0 of the overlay.
#[inline]
pub fn hdr_flags(pkt: &[u8]) -> u8 {
    *pkt.first().unwrap_or(&0)
}
/// gre.h:33 `uint8_t version` — byte 1.
#[inline]
pub fn hdr_version(pkt: &[u8]) -> u8 {
    *pkt.get(1).unwrap_or(&0)
}
/// gre.h:36-:38 `get_version() { return version & 0x07; }` — the switch
/// discriminant read (cc:183).
#[inline]
pub fn gre_get_version(pkt: &[u8]) -> u8 {
    hdr_version(pkt) & 0x07
}
/// gre.h:39-:41 `proto() { return (ProtocolId)ntohs(ether_type); }` —
/// the wire bytes 2-3 read BIG-endian (the LE-host memcpy + ntohs pair
/// collapses to the BE read; the next=34827 face build.sh :344-:353
/// decomposes at the ground ETHERTYPE_PPP 0x880B, protocol_ids.h:152).
#[inline]
pub fn gre_proto(pkt: &[u8]) -> ProtocolId {
    u16::from_be_bytes([*pkt.get(2).unwrap_or(&0), *pkt.get(3).unwrap_or(&0)])
}
/// gre.h:43-:45 `raw_proto() { return ether_type; }` — the RAW slot
/// (cppcheck-suppressed entry retained upstream; NO vector reads it —
/// port-by-reading pin).
#[inline]
pub fn gre_raw_proto(pkt: &[u8]) -> u16 {
    u16::from_le_bytes([*pkt.get(2).unwrap_or(&0), *pkt.get(3).unwrap_or(&0)])
}

/// cc:45-:54 `static const RuleMap gre_rules[]` — the SIX-row table
/// (all six CodecSid enumerators landed 18d: h:93-:98 -> 160-:165,
/// already resident codec_module.rs:107-:112) + the `{ 0, nullptr }`
/// terminator. vectors:22 `GRE rules=6 sid0=160 name=gre`; the
/// six-row grep census is build.sh :359. Side-effect note: rows 161
/// (MULTIPLE_ENCAPSULATION) and 165 (TRANS_DGRAM_LT_TRANSHDR) are
/// TABLE-ONLY — no codec_event call site touches them (measured ground
/// fact; event sites are cc:171/:189/:241/:248/:255/:270/:276 only).
pub const GRE_RULES: [RuleMap; 7] = [
    RuleMap {
        sid: CodecSid::DECODE_GRE_DGRAM_LT_GREHDR as u32, // 160
        msg: Some("GRE header length > payload length"), // cc:47 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GRE_MULTIPLE_ENCAPSULATION as u32, // 161
        msg: Some("multiple encapsulations in packet"), // cc:48 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GRE_INVALID_VERSION as u32, // 162
        msg: Some("invalid GRE version"), // cc:49 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GRE_INVALID_HEADER as u32, // 163
        msg: Some("invalid GRE header"), // cc:50 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GRE_V1_INVALID_HEADER as u32, // 164
        msg: Some("invalid GRE v.1 PPTP header"), // cc:51 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR as u32, // 165
        msg: Some("GRE trans header length > payload length"), // cc:52 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:53 terminator
];

/// cc:56-:63 `class GreModule : public BaseCodecModule` —
/// get_rules() override cc:58-:60.
#[derive(Debug)]
pub struct GreModule {
    pub base: BaseCodecModule,
}

impl GreModule {
    /// cc:59 `GreModule() : BaseCodecModule(CD_GRE_NAME, CD_GRE_HELP) { }`
    pub fn new() -> GreModule {
        GreModule {
            base: BaseCodecModule::new(CD_GRE_NAME, CD_GRE_HELP),
        }
    }

    /// cc:58-:60 `{ return gre_rules; }`.
    pub fn get_rules() -> &'static [RuleMap] {
        &GRE_RULES
    }

    /// vectors:22 `name=gre`.
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for GreModule {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:65-:77 `class GreCodec : public Codec` — anonymous-namespace
/// class; the six virtuals map to the fns below (get_protocol_ids
/// :70, decode :71, log :72, encode :73-:74, update :75-:76; the
/// name slot via Codec(CD_GRE_NAME) cc:68 rides the record).
#[derive(Default)]
pub struct GreCodec;

impl GreCodec {
    /// cc:68 `GreCodec() : Codec(CD_GRE_NAME) { }`
    pub fn new() -> GreCodec {
        GreCodec
    }

    /// cc:101-:103 `v.emplace_back(ProtocolId::GRE)` — protocol_ids.h
    /// GRE = 47 (build.sh :355 pins `GRE = 47,`; the LANDED home
    /// protocol_id::GRE = 47, codec.rs:139 — reused, no new const).
    /// vectors:21 `GREPID 47 n=1`.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::GRE); // cc:102
    }

    /// cc:108-:125 update, statement order VERBATIM. The `ip::IpApi&`
    /// operand is UNUSED (cc:111) like the gtp row -> `&()`. The uint32
    /// accumulate is wrapping (every C unsigned pair, skill rule).
    /// vectors:26 `UPD chksum-bytes 127 255 ul=8` = the cksum_add arm
    /// over the updated_len window (cc:120-:123: zero the cksum field
    /// at bytes 4-5 — the LE memcpy of `const uint16_t zero` clears
    /// BOTH bytes, operand identity kept — sum, write the u16 value
    /// back LE). The cc:118 `assert(lyr_len >= 6)` is a debug-build
    /// assert the -O0 harness build never hits (probe lyrs ≥ 6); NO
    /// Rust twin (deviations row 18g, asserts-stay-out ruling).
    pub fn update(
        &self,
        _api: &(),
        _flags: EncodeFlags,
        raw_pkt: &mut [u8],
        lyr_len: u16,
        updated_len: &mut u32,
    ) {
        // cc:112 the GREHdr overlay (field reads ride the gre.h face above).
        // cc:114 `updated_len += lyr_len;` — BEFORE any field work, and
        // the cksum window at cc:122 is `updated_len` bytes (NOT lyr_len)
        // — operand identity per arm kept.
        *updated_len = updated_len.wrapping_add(u32::from(lyr_len));

        if gre_chksum(hdr_flags(raw_pkt)) != 0 {
            // cc:120-:121 zero the checksum field (uint16 LE memcpy face
            // on the pinned LE host -> bytes 4-5; the cc:116 guard window
            // is the caller's real buffer, probe fixture >= 6).
            raw_pkt[4] = 0; // cc:120-:121 (a uint16 LE memcpy clears
            raw_pkt[5] = 0; // both bytes — same-window operand kept)
            // cc:122 `checksum::cksum_add(raw_pkt, updated_len)` — the
            // landed 18b port handles the walk; the declared-len ==
            // window pin rides checksum.rs (declared len > real buffer
            // = C OOB walk = Rust index panic posture, never exercised
            // by the pinned UPD face: ul 8 over up[16]).
            let value = crate::codecs::checksum::cksum_add(raw_pkt, *updated_len as usize);
            // cc:123 the LE u16 write-back (memcpy of uint16;
            // vectors up[4]=127 up[5]=255 = value 0xff7f LE).
            raw_pkt[4..6].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// cc:127-:165 encode, statement order VERBATIM. vectors:23
    /// `ENC lt-grehdr -> 0` is the ground TEST_CASE's own subject face
    /// (1-byte Buffer, raw_len GRE_HEADER_LEN+1 -> the `!buf.allocate`
    /// gate at cc:130-:131) and vectors:24 the allocate-ok face. The
    /// `Flow*` operand is UNNAMED in C (cc:128) — the never-read
    /// posture, dropped like the sibling rows.
    #[allow(clippy::needless_return)] // literal C flow kept readable
    #[allow(clippy::collapsible_if)] // the bounded out-of-window substitution shape (deviations row 18g)
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // cc:130-:131 `if (!buf.allocate(raw_len)) return false;` — the
        // NON-inverted form (contrast the gtp cc:228 inversion, 18f):
        // (end + len) > max_len fails the 1-byte buffer at raw_len 5.
        if !buf.allocate(u32::from(raw_len)) {
            return false;
        }

        // cc:133-:134 the overlay alias + memcpy: in C `greh_out`
        // ALIASES buf.data() written by the copy, so every later
        // greh_out->... read sees the copied bytes. Rust mirrors with
        // the copy first, then the field reads through the same window.
        if let Some(d) = buf.data_mut() {
            let n = usize::from(raw_len).min(d.len()).min(raw_in.len());
            d[..n].copy_from_slice(&raw_in[..n]);
        }

        // cc:135-:136 enc writes (operand identity: IpProtocol::GRE 47
        // -- vectors:24 nproto=47; next_ethertype = proto() over the
        // ALIASED window -- vectors:24 netype=2048 = 0x0800 BE face).
        enc.next_proto = ip_protocol::GRE;
        enc.next_ethertype = gre_proto(buf_window(buf));

        // cc:138-:152 the SEQ arm (operand per arm): `uint16_t len = 4`
        // then +4 for CHKSUM, +4 for KEY (GRE V1 key slot); the u32
        // sequence memcpy (LE read), htonl(ntohl(x)+1) round-trip ==
        // BE +1, then the LE write-back.
        let flags = gre_hdr_flags(buf);
        if gre_seq(flags) != 0 {
            let mut len: u16 = 4; // cc:140 "Flags, version and protocol"
            if gre_chksum(flags) != 0 {
                len = len.wrapping_add(4); // cc:142-:143
            }
            if gre_key(flags) != 0 {
                len = len.wrapping_add(4); // cc:145-:146
            }
            // cc:148-:151 the memcpy(&sequence, buf.data() + len, 4) +
            // htonl(ntohl(sequence) + 1) + write-back. THE OUT-OF-WINDOW
            // C FACE (deviations row 18g): on the pinned ENC ok arm the
            // slot buf.data()+8 sits PAST the 8-byte window -- and the
            // probe's own backing (back[64] at p=back+32) ENDS exactly
            // there, so C reads/writes 4 bytes into stack slack (real
            // UB the -O0 probe survives). The port implements the
            // defined bounded form (window-only, skill UB rule: never
            // replicate the overrun): the write fires ONLY when the slot
            // sits fully inside the window (unit-armed in
            // tests/gre_parity_test.rs gre_encode_seq_unit, CC flags
            // 0xB0 -> slot 12 < win 16); on the vectors arm the skip is
            // MEASURED zero-contribution -- the summed window, the
            // write-back pair and every printed field byte-match the C
            // run (both O0==O2).
            let off = usize::from(len);
            let win = buf.data().map(|d| d.len()).unwrap_or(0);
            if off + 4 <= win {
                if let Some(d) = buf.data_mut() {
                    let seq = u32::from_be_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]]);
                    let seq = seq.wrapping_add(1); // cc:150 tohost +1 on the net face
                    d[off..off + 4].copy_from_slice(&seq.to_be_bytes());
                }
            }
        }

        // cc:154-:162 the CHKSUM arm -- same zero-field/cksum_add over
        // `buf.size()` (cc:160 -- the FULL allocated window, NOT
        // raw_len twice) / LE write-back pair as update. vectors:24
        // `cksum-bytes 103 255` = value 0xff67 LE over the zeroed
        // [90,00,08,00,00,00,00,00] window (sum 0x98 -> ~ -> (u16)).
        if gre_chksum(flags) != 0 {
            // cc:156 assert(raw_len >= 6) debug-only, no Rust twin
            // (update's cite).
            let size = buf.size() as usize;
            if let Some(d) = buf.data_mut() {
                if d.len() >= 6 {
                    d[4] = 0;
                    d[5] = 0;
                }
                let value = crate::codecs::checksum::cksum_add(d, size.min(d.len()));
                if d.len() >= 6 {
                    d[4..6].copy_from_slice(&value.to_le_bytes());
                }
            }
        }

        // cc:164
        true
    }

    /// cc:167-:286 out-of-line decode, statement order VERBATIM. The
    /// `DecodeData&` operand is UNNAMED (never read -- no ports seam).
    /// `sink` carries the seven measured codec_event sites
    /// (cc:171/:189/:241/:248/:255/:270/:276, build.sh :69-:72 pins four
    /// of the sed lines); `bypass` is the left-open hook for the cc:280
    /// conf read (module doc).
    #[allow(clippy::collapsible_if)] // literal C nesting kept (codec.rs:610 precedent)
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        bypass: &mut dyn FnMut(u16) -> bool,
        sink: QueueSink<'_>,
    ) -> bool {
        // cc:169-:173 short guard -> EV 160 (vectors:3/:7 face).
        if raw.len < GRE_HEADER_LEN {
            codec_event_gre(codec, CodecSid::DECODE_GRE_DGRAM_LT_GREHDR as u32, sink);
            return false;
        }

        // cc:175-:181 the header-walk note (GRE has no header-length
        // field -- walk to find it). cc:182-:183 the overlay + `len =
        // GRE_HEADER_LEN`.
        let mut len: u32 = GRE_HEADER_LEN;

        // cc:184 the version switch (discriminant gre_get_version --
        // the & 0x07 mask face: probe f[1]=0x08 lands on CASE 0 with
        // GRE_FLAGS set -> 163, vectors:9).
        match gre_get_version(raw.data) {
            // ---- cc:185-:233 case 0x00 ----
            0x00 => {
                // cc:187-:201 the must-not-be-set guard, then the three
                // option walks, operand per arm.
                if gre_recur(hdr_flags(raw.data)) != 0 || gre_flags(hdr_version(raw.data)) != 0 {
                    codec_event_gre(codec, CodecSid::DECODE_GRE_INVALID_HEADER as u32, sink);
                    return false; // cc:189-:190
                }

                // cc:193-:194 CHKSUM||ROUTE -> +CHKSUM_LEN +OFFSET_LEN
                // (a SINGLE statement adds BOTH: operand identity kept).
                if gre_chksum(hdr_flags(raw.data)) != 0 || gre_route(hdr_flags(raw.data)) != 0 {
                    len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;
                }
                // cc:196-:197 KEY -> +KEY_LEN
                if gre_key(hdr_flags(raw.data)) != 0 {
                    len += GRE_KEY_LEN;
                }
                // cc:199-:200 SEQ -> +SEQ_LEN (the vectors:13 seq-long
                // face: 4+4 > 4 -> EV 160 via the cc:274 second guard).
                if gre_seq(hdr_flags(raw.data)) != 0 {
                    len += GRE_SEQ_LEN;
                }

                // cc:204-:231 the SRE walk, literal per-statement: len
                // advances +4 BEFORE the bound check (cc:210-:213), the
                // read cursor LAGS len by exactly 1 (len moves 4+l, the
                // cursor 3+l) -- so every sre_ptr read after the check
                // lands at or below len-1 <= raw.len-1: IN BOUNDS, no C
                // overrun anywhere in this loop (measured operand
                // arithmetic, not a posture substitution). NO pinned
                // vector arms ROUTE at all (the gre probe carries no
                // ROUTE face); the .get-or-0 reads below never fire in
                // replay -- they exist only so a non-pinned short input
                // is panic-free where C would deref (same posture as the
                // landed check_ipv6_hop_options).
                if gre_route(hdr_flags(raw.data)) != 0 {
                    let mut sre_ptr = len as usize; // cc:206

                    loop {
                        // cc:210 `len += GRE_SRE_HEADER_LEN;` BEFORE the
                        // bound check -- kept per-statement.
                        len = len.wrapping_add(GRE_SRE_HEADER_LEN);

                        // cc:212-:213 `if (len > raw.len) break;`
                        if len > raw.len {
                            break;
                        }

                        // cc:215-:217 memcpy(u16) + ntohs == BE read.
                        let sre_addrfamily = u16::from_be_bytes([
                            *raw.data.get(sre_ptr).unwrap_or(&0),
                            *raw.data.get(sre_ptr + 1).unwrap_or(&0),
                        ]);

                        // cc:219-:220 skip + sizeof(uint16) then the
                        // sre_offset byte (NEVER read -- cursor skip only).
                        sre_ptr += 2;
                        sre_ptr += 1; // cc:220 `sre_ptr += sizeof(uint8_t)`

                        // cc:222-:223 sre_length byte + cursor skip.
                        let sre_length = *raw.data.get(sre_ptr).unwrap_or(&0);
                        sre_ptr += 1;

                        // cc:225-:226 the terminating all-zero entry.
                        if sre_addrfamily == 0 && sre_length == 0 {
                            break;
                        }

                        // cc:228-:229 both cursors advance.
                        len = len.wrapping_add(u32::from(sre_length));
                        sre_ptr += usize::from(sre_length);
                    }
                }
            }

            // ---- cc:235-:267 case 0x01 (PPTP) ----
            0x01 => {
                // cc:238-:243 five-OR never-present guard -> EV 164
                // (vectors:14 the V1_FLAGS 0x08 face).
                if gre_chksum(hdr_flags(raw.data)) != 0
                    || gre_route(hdr_flags(raw.data)) != 0
                    || gre_ssr(hdr_flags(raw.data)) != 0
                    || gre_recur(hdr_flags(raw.data)) != 0
                    || gre_v1_flags(hdr_version(raw.data)) != 0
                {
                    codec_event_gre(codec, CodecSid::DECODE_GRE_V1_INVALID_HEADER as u32, sink);
                    return false;
                }

                // cc:245-:250 the protocol must be 0x880B PPP guard ->
                // EV 164 (vectors:16 the etype-0 face; gre_proto's BE
                // read matches greh->proto()).
                if gre_proto(raw.data) != PROTOCOL_ID_ETHERTYPE_PPP {
                    codec_event_gre(codec, CodecSid::DECODE_GRE_V1_INVALID_HEADER as u32, sink);
                    return false;
                }

                // cc:252-:257 the always-present KEY guard -> EV 164
                // (vectors:18 the flags-0 face).
                if gre_key(hdr_flags(raw.data)) == 0 {
                    codec_event_gre(codec, CodecSid::DECODE_GRE_V1_INVALID_HEADER as u32, sink);
                    return false;
                }

                // cc:259-:265 the length walk: +KEY_LEN always, +SEQ_LEN
                // on SEQ, +V1_ACK_LEN on V1_ACK (never vector-arm
                // SEQ/ACK here -- unit face).
                len += GRE_KEY_LEN;
                if gre_seq(hdr_flags(raw.data)) != 0 {
                    len += GRE_SEQ_LEN;
                }
                if gre_v1_ack(hdr_version(raw.data)) != 0 {
                    len += GRE_V1_ACK_LEN;
                }
            }

            // ---- cc:269-:271 default: EV 162 (vectors:20 badver2) ----
            _ => {
                codec_event_gre(codec, CodecSid::DECODE_GRE_INVALID_VERSION as u32, sink);
                return false;
            }
        }

        // cc:274-:278 the SECOND long-guard face (both v0 walk faces:
        // chksum-long vectors:11, seq-long vectors:13).
        if len > raw.len {
            codec_event_gre(codec, CodecSid::DECODE_GRE_DGRAM_LT_GREHDR as u32, sink);
            return false;
        }

        // cc:280-:281 the bypass arm -- left-open hook (module doc).
        if bypass(TUNNEL_GRE) {
            codec.tunnel_bypass = true;
        }

        // cc:283-:285 the success trio, operand per arm: lyr static cast
        // u32 -> u16 trunc face kept as wrapping (vectors:19 lyr=8),
        // next_prot_id = proto() (vectors:19 next=34827 the 0x880B BE
        // face), flags |= NON_IP_TUNNEL | ETHER_NEXT (0x0200 | 0x1000 =
        // 4608, both constexprs build.sh-asserted at the ground
        // codec.h:104/:106 -- CODEC_ETHER_NEXT landed 18c-adjacent,
        // codec.rs:54).
        codec.lyr_len = len as u16; // cc:283 static_cast<uint16_t> trunc face
        codec.next_prot_id = gre_proto(raw.data);
        codec.codec_flags |= CODEC_NON_IP_TUNNEL | CODEC_ETHER_NEXT;
        // cc:286 no PROTO_BIT__GRE exists ground-side (build.sh :337-:339
        // greps decode_data.h == 0 hits) -> the bits=0 honest arm
        // (vectors:19) is BY CONSTRUCTION, no proto_bits write.
        true
    }

    /// cc:289-:297 log. NEVER vectorized (the probe never calls log() --
    /// vectors carry no log lines; the 18d eth log posture): the
    /// TextLog_Print format string lands literal at the ordered sink:
    /// cc:294 `"version:%u flags:0x%02X ethertype:(0x%04X)"` -> %u
    /// decimal / %02X / %04X upper-hex, the `(0x%04X)` PARENS are part
    /// of the ground string (contrast the eth pair), static_cast
    /// uint16_t(proto()) kept.
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        sink(format!(
            "version:{} flags:0x{:02X} ethertype:(0x{:04X})",
            gre_get_version(raw_pkt), // cc:295 greh->get_version()
            hdr_flags(raw_pkt),       // cc:295 greh->flags
            gre_proto(raw_pkt) as u16, // cc:296 static_cast<uint16_t>(greh->proto())
        )); // cc:294
    }
}

/// Window face for the encode alias reads (C `greh_out == buf.data()`):
/// the pinned allocate-ok window is always valid post-allocate (end != 0
/// the Buffer rule); the zero-size window is the never-armed C-invalid-
/// pointer face -> empty slice (the defined stand-in, deviations face
/// shared with the gtp encode cite).
fn buf_window<'b>(buf: &'b Buffer<'_>) -> &'b [u8] {
    buf.data().unwrap_or(&[])
}
/// The flags operand at the encode arms (C re-derefs greh_out->flags at
/// every macro -- same aliased window).
fn gre_hdr_flags(buf: &Buffer<'_>) -> u8 {
    hdr_flags(buf_window(buf))
}

/// The seven codec_event sites ride the LANDED framework/codec.rs
/// codec_event (GID_DECODE 116 -> the vectors `EV 116 <sid>` family).
#[inline]
fn codec_event_gre(codec: &CodecData, sid: u32, sink: QueueSink) {
    crate::framework::codec::codec_event(codec, sid, sink);
}

// cc:303-:304 `static Module* mod_ctor() { return new GreModule; }` +
// cc:306-:307 mod_dtor -- the mod pair is SET (contrast the 18f teredo
// nullptr arm): vectors_faceA:5 `GRE mod_ctor=1 mod_dtor=1`, the
// cc:326-:327 record slots. cc:309-:310 ctor / cc:312-:313 dtor the
// codec pair (stack-owned drop on the Rust face, 18d posture).

/// cc:315-:335 `static const CodecApi gre_api` — vectors:1 `API gre
/// type=0 size=112 ver=1900547 name=gre` + vectors:2 HELP (and the
/// FACE-A twin); the mod pair SET (the honest contrast arm vs the 18f
/// teredo=0 asymmetry).
pub const GRE_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:318
    size: CDAPI_SIZEOF_CODEC_API, // cc:319 sizeof(CodecApi)=112
    api_version: CDAPI_VERSION,   // cc:320 1900547
    version: 0,                   // cc:321
    features: PLUGIN_SO_RELOAD,   // cc:322
    options: API_OPTIONS,         // cc:323
    name: CD_GRE_NAME,            // cc:324
    help: CD_GRE_HELP,            // cc:325
    mod_ctor: true,               // cc:326 SET (the gate-change row's own arm)
    mod_dtor: true,               // cc:327 SET
    pinit: false,                 // cc:329
    pterm: false,                 // cc:330
    tinit: false,                 // cc:331
    tterm: false,                 // cc:332
    ctor: true,                   // cc:333
    dtor: true,                   // cc:334
};

/// cc:337-:345 the table face with the REAL live arms (contrast the 18e
/// commented hopopts oddity): non-BUILDING_SO face `cd_gre[] = {
/// &gre_api.base, nullptr }` — the name ALREADY resident in
/// STATIC_CODEC_EXTERN_NAMES codec_api.rs:110 (never re-touched; the
/// dormant codec_api.cc:52 extern stays a record, not a link edge —
/// build.sh :80).
pub const CD_GRE: CodecTable = &[&GRE_API];
