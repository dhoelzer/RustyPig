//! Port of `src/codecs/ip/cd_auth.cc` (172 L) — row 18h, THE NAME-DRIFT
//! ROW of the small four (`tools/small4_harness`, ZERO-gate probe-only).
//! Ground: snort3-src @ fe29cbe, md5 `e9ce9351beeee3b7cedab63e6cede6c0`
//! wc 172 (small4 build.sh :36-:41 every build). DIR FACT: `codecs/ip/`;
//! includes ONLY the four resident headers (ZERO fresh cps, DAQ-FREE).
//!
//! THE TRUE-NAME-DRIFT FACE (the row's headline, small4 PLAN §3 + R1):
//!   file base      `cd_auth`   (cd_auth.cc)
//!   TABLE name     `cd_ah[]`   cc:166 (REAL BUILDING_SO arms :163-:167)
//!   extern         `cd_ah`     codec_api.cc :40 + load_plugins(cd_ah) :85
//!   ladder entry   "cd_ah"     codec_api.rs :98 (RESIDENT, NEVER touched)
//!   api struct     `ah_api`    cc:141
//!   NAME macro     `CD_AUTH_NAME "auth"` cc:30  -> the WALK prints
//!                  `LOAD auth` / `API ah ... name=auth` (the link
//!                  symbol cd_ah vs the printed NAME "auth" — the drift
//!                  rides THROUGH the decode face too)
//! There is NO extern named `cd_auth` ANYWHERE in ground — build.sh
//! re-runs that grep EVERY build and dies if the flip ever makes one
//! exist (`drift_cd_auth_extern.txt` stays empty). Tripwire rule
//! (codified 18g, RE-ARMED here): every grep for the table/extern/ladder
//! face uses the TABLE name `cd_ah`, NEVER the file base; the Rust-side
//! tripwire test pins the file-base-vs-extern PAIR ("cd_auth" file <->
//! "cd_ah" ladder entry) — the cd_hop_opts 18e family precedent. The
//! Rust file base stays TRUE to ground (`cd_auth.rs`), the table
//! constant carries the C table name (`CD_AH`).
//!
//! decode: the ip6 block is GUARDED here — cc:109 `snort.ip_api.is_ip6()`
//! (the esp-shaped seam: `AuthDecodeData::is_ip6`); on the ip4 face the
//! whole cc:110-:121 block is skipped (vectors:26-:27 `AH ok24 -> 1
//! lyr=24 next=6` — next = a[0] raw cast cc:106). lyr_len = 8 + (len<<2)
//! (cc:98, "8 is the number of bytes excluded in the length"), the
//! lyr>len re-check cc:100-:104 -> 466 + false (`AH badlen`: a[1]=8 ->
//! 8+32=40 > 16). MIN_AUTH_LEN = 16 (cc:79, comment "no relation to the
//! AuthHdr.len field" kept). Order check cc:117 AUTH (order 5): the
//! vectors `AH order55` arm pre-sets curr=5 -> 5<=5 -> EV 296 rides the
//! SUCCESS.
//!
//! sids resident, zero new: DECODE_AUTH_HDR_TRUNC h:218 -> 465
//! (codec_module.rs:223), DECODE_AUTH_HDR_BAD_LEN h:219 -> 466 (:224),
//! 456 :214, 296 via the landed check. vectors:21 `EV 116 465` / :23
//! `EV 116 466` x2-sited, :31 `AHRULES 2 sid0=465 name=auth` (the NAME
//! face "auth" — module->get_name() prints CD_AUTH_NAME, NOT cd_ah),
//! :30 `AHPID 51 n=1` (ProtocolId::AUTH = 51 + protocol_ids.h
//! "AUTH = 51, // RFC 4302" grep-pinned in build.sh).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CodecData, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    DECODE_IP6_EXCESS_EXT_HDR, PLUGIN_SO_RELOAD, PROTO_BIT__IP6_EXT, PT_CODEC, ProtocolId,
    QueueSink, RawData, ip_protocol, protocol_id,
};

/// cc:30 `#define CD_AUTH_NAME "auth"` — THE NAME-side of the drift
/// pair (module doc): the printed/API name is "auth" everywhere the
/// walk looks, while the link symbol is cd_ah.
pub const CD_AUTH_NAME: &str = "auth";
/// cc:31 `#define CD_AUTH_HELP "support for IP authentication header"`
pub const CD_AUTH_HELP: &str = "support for IP authentication header";

/// cc:79 `constexpr uint8_t MIN_AUTH_LEN = 16` — "this is in minimum
/// number of bytes ... no relation to the AuthHdr.len field" (the C
/// comment rides). cc:90 guard: raw.len < 16 -> 465 + false.
pub const MIN_AUTH_LEN: u8 = 16;

/// cc:35-:40 `static const RuleMap auth_rules[]` — TWO entries (the
/// 2-entry ground grep census in build.sh) + terminator. vectors:31
/// `AHRULES 2 sid0=465 name=auth` (sid0 = TRUNC 465 first).
pub const AUTH_RULES: [RuleMap; 3] = [
    RuleMap {
        sid: CodecSid::DECODE_AUTH_HDR_TRUNC as u32, // 465 (h:218)
        msg: Some("truncated authentication header"), // cc:37 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_AUTH_HDR_BAD_LEN as u32, // 466 (h:219)
        msg: Some("bad authentication header length"), // cc:38 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:39 terminator
];

/// cc:42-:49 `class AuthModule : public BaseCodecModule` — 2-arg ctor
/// (NO params: cc:45) + get_rules() override cc:47-:48. The module
/// NAME is "auth" (CD_AUTH_NAME) — the vectors RULES line pins it.
#[derive(Debug)]
pub struct AuthModule {
    pub base: BaseCodecModule,
}

impl AuthModule {
    pub fn new() -> AuthModule {
        AuthModule {
            base: BaseCodecModule::new(CD_AUTH_NAME, CD_AUTH_HELP), // cc:45 2-arg
        }
    }

    pub fn get_rules() -> &'static [RuleMap] {
        &AUTH_RULES
    }

    /// get_name face (Module::get_name): vectors:31 `name=auth` — the
    /// drift ride, prints "auth" NOT "ah"/"cd_auth".
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for AuthModule {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:65-:77 `struct AuthHdr` ("Valid for both IPv4 and IPv6"):
/// next @0, len @1, rsv 2, spi 4, seq 4, icv[1]. R3 face: the decode
/// reads ONLY bytes 0/1; the rest stay unread (no symbol poking).
/// cc:79 MIN_AUTH_LEN is the guard, NOT sizeof-driven.
#[derive(Copy, Clone, Default)]
pub struct AuthDecodeData {
    pub is_ip6: bool, // cc:109 snort.ip_api.is_ip6()
}

#[derive(Default)]
pub struct AuthCodec;

impl AuthCodec {
    /// cc:58 `AuthCodec() : Codec(CD_AUTH_NAME) { }` — the Codec base
    /// name is the MACRO "auth" (drift pair side one).
    pub fn new() -> AuthCodec {
        AuthCodec
    }

    /// cc:83-:84 out-of-line def — vectors:30 `AHPID 51 n=1`
    /// (ProtocolId::AUTH = 51).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::AUTH); // cc:84
    }

    /// cc:86-:123 out-of-line decode, statement order VERBATIM.
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &AuthDecodeData,
        sink: QueueSink,
    ) -> bool {
        // cc:90-:94: raw.len < MIN_AUTH_LEN (16) -> 465 + false.
        // vectors:21/:22 `EV 116 465` + `AH short15 -> 0`.
        if raw.len < (MIN_AUTH_LEN as u32) {
            crate::framework::codec::codec_event(codec, AUTH_HDR_TRUNC_SID, sink); // cc:92
            return false;
        }

        // cc:98: lyr_len = 8 + (ah->len << 2) — byte 1 (the "8 bytes
        // excluded" comment rides).
        let ah_len = *raw.data.get(1).unwrap_or(&0); // AuthHdr::len @1
        codec.lyr_len = (8u32 + ((ah_len as u32) << 2)) as u16;

        // cc:100-:104: lyr_len > raw.len -> 466 + false. vectors:23/:24
        // `EV 116 466` + `AH badlen -> 0` (a[1]=8 -> 40 > 16).
        if (codec.lyr_len as u32) > raw.len {
            crate::framework::codec::codec_event(codec, AUTH_HDR_BAD_LEN_SID, sink); // cc:102
            return false;
        }

        // cc:106 next_prot_id = (ProtocolId)ah->next (byte 0; ip4 ok
        // face vectors:26-:27 next=6 off a[0]).
        let ah_next = *raw.data.first().unwrap_or(&0); // AuthHdr::next @0
        codec.next_prot_id = ah_next as ProtocolId;

        // cc:108-:121 "// must be called AFTER setting next_prot_id" —
        // the GUARDED ip6 block (esp shape): maxopts -> 456 + false
        // (vectors:28/:29 `AH maxopts -> 0`); order check cc:117 AUTH;
        // then the three writes.
        if snort.is_ip6 {
            let hit = codec
                .conf
                .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
                .unwrap_or(false);
            if hit {
                crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, sink); // cc:113
                return false;
            }
            crate::framework::codec::check_ipv6_extension_order(codec, ip_protocol::AUTH, sink); // cc:117
            codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:118
            codec.ip6_csum_proto = ah_next; // cc:119 (IpProtocol, no cast)
            codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:120
        }
        true // cc:122
    }
}

/// resident sids (codec_module.rs:223/:224, h:218/:219 walk cites —
/// zero new constants).
const AUTH_HDR_TRUNC_SID: u32 = CodecSid::DECODE_AUTH_HDR_TRUNC as u32;
const AUTH_HDR_BAD_LEN_SID: u32 = CodecSid::DECODE_AUTH_HDR_BAD_LEN as u32;

// cc:129-:139 static mod_ctor/mod_dtor + ctor/dtor — ALL FOUR slots
// live (vectors_faceA `ah mod_ctor=1 mod_dtor=1` — the API tag there is
// "ah", the probe's shorthand for the cd_ah table; the NAME inside stays
// "auth" on the record face).

/// cc:141-:161 `static const CodecApi ah_api` — THE DRIFT-SITE record:
/// C identifier `ah_api` (cc:141) while the file is cd_auth.cc and the
/// NAME slot carries "auth". Rust identifier keeps the C name.
pub const AH_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:144
    size: CDAPI_SIZEOF_CODEC_API, // cc:145 (112 probe pin)
    api_version: CDAPI_VERSION, // cc:146 (1900547)
    version: 0,      // cc:147
    features: PLUGIN_SO_RELOAD, // cc:148
    options: API_OPTIONS, // cc:149
    name: CD_AUTH_NAME, // cc:150 -> "auth"
    help: CD_AUTH_HELP, // cc:151
    mod_ctor: true,  // cc:152 SET
    mod_dtor: true,  // cc:153 SET
    pinit: false,    // cc:155
    pterm: false,    // cc:156
    tinit: false,    // cc:157
    tterm: false,    // cc:158
    ctor: true,      // cc:159
    dtor: true,      // cc:160
};

/// cc:163-:171 the export — THE DRIFT FACE: table constant named
/// `CD_AH` mirroring the C table `cd_ah[]` at cc:166 (REAL BUILDING_SO
/// arms :163-:167, sed-pin `const BaseApi* cd_ah[] =` in build.sh),
/// feeding `&ah_api.base`. The FILE is cd_auth.rs; the ladder entry is
/// "cd_ah" (codec_api.rs:98) — the pair the tripwire test pins.
pub const CD_AH: CodecTable = &[&AH_API];
